/*
 * host-power-module.c
 *
 * XCPMD module that provides display power management actions.
 *
 * Copyright (c) 2016 Assured Information Security, Inc.
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
#include "rules.h"
#include "vm-utils.h"
#include "rpcgen/xenmgr_host_client.h"

#define XENMGR_HOST_PATH "/host"

//Function prototypes
void shutdown_host               (struct arg_node *);
void shutdown_host_idle          (struct arg_node *);
void restart_host                (struct arg_node *);
//sleep and hibernate, should they ever be supported, would go in this module


//Private data structures
struct action_table_row {
    char * name;
    void (* func)(struct arg_node *);
    char * prototype;
    char * pretty_prototype;
};


//Private data
static struct action_table_row action_table[] = {
    {"shutdownHost", shutdown_host, "n" , "void"} ,
    {"shutdownHostIdle", shutdown_host_idle, "n" , "void"} ,
    {"restartHost" , restart_host , "n" , "void"} 
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

    //nothing to do
    return;
}


//Actions
//Shuts down the host.
void shutdown_host(struct arg_node * args) {
    dbus_async_call("com.citrix.xenclient.xenmgr", XENMGR_HOST_PATH, "com.citrix.xenclient.xenmgr.host", com_citrix_xenclient_xenmgr_host_shutdown_async, NULL);
}

void shutdown_host_idle(struct arg_node * args) {
    dbus_async_call("com.citrix.xenclient.xenmgr", XENMGR_HOST_PATH, "com.citrix.xenclient.xenmgr.host", com_citrix_xenclient_xenmgr_host_shutdown_idle_async, NULL);
}

//Restarts the host.
void restart_host(struct arg_node * args) {
    dbus_async_call("com.citrix.xenclient.xenmgr", XENMGR_HOST_PATH, "com.citrix.xenclient.xenmgr.host", com_citrix_xenclient_xenmgr_host_reboot_async, NULL);
}
