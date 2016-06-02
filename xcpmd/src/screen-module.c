/*
 * screen-module.c
 *
 * XCPMD module that provides display power management actions.
 *
 * Copyright (c) 2015 Assured Information Security, Inc.
 *
 * Author:
 * Jennifer Temkin <temkinj@ainfosec.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "project.h"
#include "xcpmd.h"
#include "rpcgen/surfman_client.h"
#include "rules.h"
#include <math.h>

//Function prototypes
void screen_on(struct arg_node * args);
void screen_off(struct arg_node * args);
void set_backlight(struct arg_node * args);
void increase_backlight(struct arg_node * args);
void decrease_backlight(struct arg_node * args);
static int get_brightness(void);
static int get_raw_brightness(int *brightness, int *max_brightness);
static void set_brightness(int percentage);


//Private data structures
struct action_table_row {
    char * name;
    void (* func)(struct arg_node *);
    char * prototype;
    char * pretty_prototype;
};


//Private data
static struct action_table_row action_table[] = {
    {"screenOn"          , screen_on          , "n" , "void"                    } ,
    {"screenOff"         , screen_off         , "n" , "void"                    } ,
    {"setBacklight"      , set_backlight      , "i" , "int backlight_percent"   } ,
    {"increaseBacklight" , increase_backlight , "i" , "int percent_to_increase" } ,
    {"decreaseBacklight" , decrease_backlight , "i" , "int percent_to_decrease" }
};

static unsigned int num_action_types = sizeof(action_table) / sizeof(action_table[0]);


//Registers this module's action types.
//The constructor attribute causes this function to run at load (dlopen()) time.
__attribute__ ((constructor)) static void init_module() {

    unsigned int i;

    for (i=0; i < num_action_types; ++i) {
        add_action_type(action_table[i].name, action_table[i].func, action_table[i].prototype, action_table[i].pretty_prototype);
    }
}


//Cleans up after this module.
//The destructor attribute causes this to run at unload (dlclose()) time.
__attribute__ ((destructor)) static void uninit_module() {

    return;
}


//Actions
//Turns all screens on.
void screen_on(struct arg_node * args) {
    com_citrix_xenclient_surfman_dpms_on_(xcdbus_conn, SURFMAN_SERVICE, SURFMAN_PATH);
}


//Turns all screens off.
void screen_off(struct arg_node * args) {
    com_citrix_xenclient_surfman_dpms_off_(xcdbus_conn, SURFMAN_SERVICE, SURFMAN_PATH);
}


//Sets the backlight to as close to the desired percentage as surfman allows.
void set_backlight(struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    set_brightness(node->arg.i);
}


//Increases the backlight by as close to the current percentage as surfman allows.
void increase_backlight(struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    int old_backlight, new_backlight;

    old_backlight = get_brightness();
    if (old_backlight < 0) {
        return;
    }

    new_backlight = old_backlight + node->arg.i;

    if (new_backlight > 100) {
        new_backlight = 100;
    }
    else if (new_backlight < old_backlight) {
        new_backlight = old_backlight;
    }

    set_brightness(new_backlight);
}


//Increases the backlight by as close to the current percentage as surfman allows.
void decrease_backlight(struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    int old_backlight, new_backlight;

    old_backlight = get_brightness();
    if (old_backlight < 0) {
        return;
    }

    new_backlight = old_backlight - node->arg.i;

    if (new_backlight < 0) {
        new_backlight = 0;
    }
    else if (new_backlight > old_backlight) {
        new_backlight = old_backlight;
    }

    set_brightness(new_backlight);
}


//Get the raw backlight values.
static int get_raw_brightness(int * brightness, int * max_brightness) {

    DIR *sys_dir = NULL;
    struct dirent * dp;
    FILE * file = NULL;
    char data[128];
    char *device_name = NULL, *path = NULL;

    if (brightness == NULL && max_brightness == NULL) {
        xcpmd_log(LOG_DEBUG, "get_brightness called with null args?");
        goto fail;
    }

    //Get the backlight directory.
    sys_dir = opendir(BACKLIGHT_PATH);
    if (!sys_dir) {
        xcpmd_log(LOG_WARNING, "Couldn't open backlight dir %s - error %d\n", BACKLIGHT_PATH, errno);
        goto fail;
    }

    //There can be more than one backlight device, and the names of these
    //devices may vary from platform to platform. They should all report
    //correct values, so just choose the first one.
    while ((dp = readdir(sys_dir)) != NULL) {
        if (dp->d_type == DT_LNK) {
            device_name = clone_string(dp->d_name);
            break;
        }
    }
    if (device_name == NULL) {
        xcpmd_log(LOG_WARNING, "No backlight devices found in %s\n", BACKLIGHT_PATH);
        goto fail;
    }
    closedir(sys_dir);
    sys_dir = NULL;

    //Get the current brightness and max brightness.
    if (brightness != NULL) {
        path = safe_sprintf("%s/%s/%s", BACKLIGHT_PATH, device_name, "actual_brightness");
        file = fopen(path, "r");
        if (file == NULL) {
            xcpmd_log(LOG_WARNING, "Couldn't open file %s - error %d\n", path, errno);
            goto fail;
        }

        fgets(data, sizeof(data), file);
        *brightness = atoi(data);
        fclose(file);
        free(path);
        file = NULL;
        path = NULL;
    }

    if (max_brightness != NULL) {
        path = safe_sprintf("%s/%s/%s", BACKLIGHT_PATH, device_name, "max_brightness");
        file = fopen(path, "r");
        if (file == NULL) {
            xcpmd_log(LOG_WARNING, "Couldn't open file %s - error %d\n", path, errno);
            goto fail;
        }
    
        fgets(data, sizeof(data), file);
        *max_brightness = atoi(data);
        fclose(file);
        free(path);
        file = NULL;
        path = NULL;
    }
    free(device_name);
    device_name = NULL;

    return 0;

fail:

    if (sys_dir) {
        closedir(sys_dir);
    }

    if (file) {
        fclose(file);
    }

    if (path) {
        free(path);
    }

    if (device_name) {
        free(device_name);
    }

    return -1;
}


//Get the current backlight value in percent.
static int get_brightness(void) {
    
    int brightness, max_brightness, percent;

    if (get_raw_brightness(&brightness, &max_brightness) != 0)
        return -1;

    //Convert backlight to percent.
    if (max_brightness == 0) {
        percent = 0;
    }
    else {
        percent = (brightness * 100) / max_brightness;
    }

    return percent;
}


//Surfman doesn't have a method to set this directly, so we have to do it the
//roundabout way.
static void set_brightness(int percent) {

    int brightness, max_brightness, desired_brightness;
    int surfman_step_size, desired_steps, current_steps, steps_to_take;
    int i;

    if (get_raw_brightness(&brightness, &max_brightness) != 0) {
        xcpmd_log(LOG_WARNING, "Couldn't set brightness; unable to read current brightness.");
        return;
    }

    //Surfman currently supports 15 levels of brightness. Get the step size.
    surfman_step_size = max_brightness / 15;

    //Bounds-check our requested brightness.
    if (percent > 100) {
        percent = 100;
    }
    else if (percent < 0) {
        percent = 0;
    }

    //Determine the desired brightness.
    desired_brightness = (percent * max_brightness) / 100;

    //Determine how many times we'll need to ask surfman to change the brightness.
    current_steps = brightness / surfman_step_size;
    desired_steps = round((float)desired_brightness / (float)surfman_step_size);
    steps_to_take = desired_steps - current_steps;

    //Adjust brightness.
    if (steps_to_take > 0) {
        for (i = 0; i < steps_to_take; ++i) {
            com_citrix_xenclient_surfman_increase_brightness_(xcdbus_conn, SURFMAN_SERVICE, SURFMAN_PATH);
        }
    }
    else if (steps_to_take < 0) {
        for (i = 0; i > steps_to_take; --i) {
            com_citrix_xenclient_surfman_decrease_brightness_(xcdbus_conn, SURFMAN_SERVICE, SURFMAN_PATH);
        }
    }
}
