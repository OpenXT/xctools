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
static int times_loaded = 0;


//Registers this module's action types.
//The constructor attribute causes this function to run at load (dlopen()) time.
__attribute__ ((constructor)) static void init_module() {

    unsigned int i;

    if (times_loaded > 0)
        return;

    for (i=0; i < num_action_types; ++i) {
        add_action_type(action_table[i].name, action_table[i].func, action_table[i].prototype, action_table[i].pretty_prototype);
    }
}


//Cleans up after this module.
//The destructor attribute causes this to run at unload (dlclose()) time.
__attribute__ ((destructor)) static void uninit_module() {

    --times_loaded;

    //if (times_loaded > 0)
    //    return;

    return;
}


//Actions
//Calls a script that asks vbetool to set DPMS=on, then asks surfman to remodeset.
void screen_on(struct arg_node * args) {
    //Automatically background the new process so we don't block on it.
    char * command = safe_sprintf("%s &", SCREEN_ON_SCRIPT);
    system(command);
    free(command);
}


//Calls a script that asks vbetool to set DPMS=off.
void screen_off(struct arg_node * args) {
    //Automatically background the new process so we don't block on it.
    char * command = safe_sprintf("%s &", SCREEN_OFF_SCRIPT);
    system(command);
    free(command);
}


//Sets the backlight to as close to the desired percentage as surfman allows.
void set_backlight(struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    set_brightness(node->arg.i);
}


//Increases the backlight by as close to the current percentage as surfman allows.
void increase_backlight(struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    unsigned int old_backlight, new_backlight;

    old_backlight = get_brightness();
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
    unsigned int old_backlight;
    int new_backlight;

    old_backlight = get_brightness();
    new_backlight = old_backlight - node->arg.i;

    if (new_backlight < 0) {
        new_backlight = 0;
    }
    else if ((unsigned)new_backlight > old_backlight) {
        new_backlight = old_backlight;
    }

    set_brightness((unsigned int)new_backlight);
}


//Get the current backlight in percent.
static int get_brightness(void) {

    DIR *sys_dir, *backlight_dir;
    struct dirent * dp;
    FILE * file;
    char data[128];
    char *device_name = NULL, *path = NULL;
    int brightness, max_brightness, percent;

    //Get the backlight directory.
    sys_dir = opendir(BACKLIGHT_PATH);
    if (!sys_dir) {
        xcpmd_log(LOG_WARNING, "Couldn't open backlight dir %s - error %d\n", BACKLIGHT_PATH, errno);
        return 0;
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
        closedir(sys_dir);
        return 0;
    }
    closedir(sys_dir);

    //Get the current brightness and max brightness.
    path = safe_sprintf("%s/%s/%s", BACKLIGHT_PATH, device_name, "actual_brightness");
    file = fopen(path, "r");
    if (file == NULL) {
        xcpmd_log(LOG_WARNING, "Couldn't open file %s - error %d\n", path, errno);
        free(path);
        return 0;
    }

    fgets(data, sizeof(data), file);
    brightness = atoi(data);
    fclose(file);
    free(path);

    path = safe_sprintf("%s/%s/%s", BACKLIGHT_PATH, device_name, "max_brightness");
    file = fopen(path, "r");
    if (file == NULL) {
        xcpmd_log(LOG_WARNING, "Couldn't open file %s - error %d\n", path, errno);
        free(path);
        return 0;
    }

    fgets(data, sizeof(data), file);
    max_brightness = atoi(data);
    fclose(file);
    free(path);

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

    DIR *sys_dir, *backlight_dir;
    struct dirent * dp;
    FILE * file;
    char data[128];
    char *device_name = NULL, *path = NULL;
    int brightness, max_brightness, desired_brightness;
    int surfman_step_size, desired_steps, current_steps, steps_to_take;
    int i;

    //Get the backlight directory.
    sys_dir = opendir(BACKLIGHT_PATH);
    if (!sys_dir) {
        xcpmd_log(LOG_WARNING, "Couldn't open backlight dir %s - error %d\n", BACKLIGHT_PATH, errno);
        return;
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
        closedir(sys_dir);
        return;
    }
    closedir(sys_dir);

    //Get the current brightness and max brightness.
    path = safe_sprintf("%s/%s/%s", BACKLIGHT_PATH, device_name, "actual_brightness");
    file = fopen(path, "r");
    if (file == NULL) {
        xcpmd_log(LOG_WARNING, "Couldn't open file %s - error %d\n", path, errno);
        free(path);
        return;
    }

    fgets(data, sizeof(data), file);
    brightness = atoi(data);
    fclose(file);
    free(path);

    path = safe_sprintf("%s/%s/%s", BACKLIGHT_PATH, device_name, "max_brightness");
    file = fopen(path, "r");
    if (file == NULL) {
        xcpmd_log(LOG_WARNING, "Couldn't open file %s - error %d\n", path, errno);
        free(path);
        return;
    }

    fgets(data, sizeof(data), file);
    max_brightness = atoi(data);
    fclose(file);
    free(path);
    free(device_name);

    //Surfman currently supports 15 levels of brightness. Get the step size.
    surfman_step_size = max_brightness / 15;

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
