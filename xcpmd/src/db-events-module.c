/*
 * idle-detect-module.c
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
#include "rules.h"
#include "modules.h"
#include "vm-utils.h"
#include "db-events-module.h"
#include "db-helper.h"

//Function prototypes
bool var_was_written(struct ev_wrapper * event, struct arg_node * args);
bool var_int_equals(struct ev_wrapper * event, struct arg_node * args);
bool var_int_less_than(struct ev_wrapper * event, struct arg_node * args);
bool var_int_greater_than(struct ev_wrapper * event, struct arg_node * args);
bool var_float_less_than(struct ev_wrapper * event, struct arg_node * args);
bool var_float_greater_than(struct ev_wrapper * event, struct arg_node * args);
bool var_is_true(struct ev_wrapper * event, struct arg_node * args);
bool var_is_false(struct ev_wrapper * event, struct arg_node * args);
bool var_str_equals(struct ev_wrapper * event, struct arg_node * args);

//Private data structures
struct event_data_row {
    char * name;
    bool is_stateless;
    enum arg_type value_type;
    union arg_u reset_value;
    unsigned int index;
};

struct cond_table_row {
    char * name;
    bool (* func)(struct ev_wrapper *, struct arg_node *);
    char * prototype;
    char * pretty_prototype;
    unsigned int event_index;
    void (* on_instantiate)(struct condition *);
};

struct timer {
    struct list_head list;
    char * name;
};


//Private data
static struct event_data_row event_data[] = {
    { "event_var_written"     , IS_STATEFUL , ARG_STR, { .str = "" }, EVENT_VAR_WRITTEN      } ,
    { "event_var_written_edge", IS_STATELESS, ARG_STR, { .str = "" }, EVENT_VAR_WRITTEN_EDGE }
};

static struct cond_table_row condition_data[] = {
    { "whenVarWritten"   , var_was_written        , "s"   , "string var_name"  , EVENT_VAR_WRITTEN_EDGE , NULL } ,
    { "intEqualTo"       , var_int_equals         , "i i" , "int a, int b"     , EVENT_VAR_WRITTEN      , NULL } ,
    { "intGreaterThan"   , var_int_greater_than   , "i i" , "int a, int b"     , EVENT_VAR_WRITTEN      , NULL } ,
    { "intLessThan"      , var_int_less_than      , "i i" , "int a, int b"     , EVENT_VAR_WRITTEN      , NULL } ,
    { "floatGreaterThan" , var_float_greater_than , "f f" , "float a, float b" , EVENT_VAR_WRITTEN      , NULL } ,
    { "floatLessThan"    , var_float_less_than    , "f f" , "float a, float b" , EVENT_VAR_WRITTEN      , NULL } ,
    { "isTrue"           , var_is_true            , "b"   , "bool n"           , EVENT_VAR_WRITTEN      , NULL } ,
    { "isFalse"          , var_is_false           , "b"   , "bool n"           , EVENT_VAR_WRITTEN      , NULL }
};

static unsigned int num_events = sizeof(event_data) / sizeof(event_data[0]);
static unsigned int num_conditions = sizeof(condition_data) / sizeof(condition_data[0]);


//Public data
struct ev_wrapper ** _db_event_table;


//Initializes the module.
//The constructor attribute causes this function to run at load (dlopen()) time.
__attribute__((constructor)) static void init_module() {

    unsigned i;

    //Allocate space for event tables.
    _db_event_table = (struct ev_wrapper **)malloc(num_events * sizeof(struct ev_wrapper *));
    if (!(_db_event_table)) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return;
    }

    //Add all events to the event list.
    for (i=0; i < num_events; ++i) {
        struct event_data_row entry = event_data[i];
        _db_event_table[entry.index]  = add_event(entry.name, entry.is_stateless, entry.value_type, entry.reset_value);
    }

    //Add all condition_types to the condition_type list.
    for (i=0; i < num_conditions; ++i) {
        struct cond_table_row entry = condition_data[i];
        add_condition_type(entry.name, entry.func, entry.prototype, entry.pretty_prototype, _db_event_table[entry.event_index], entry.on_instantiate);
    }
}


//Cleans up after this module.
//The destructor attribute causes this to run at unload (dlclose()) time.
__attribute__((destructor)) static void uninit_module() {

    //Free event tables.
    free(_db_event_table);
}


//Condition checkers
bool var_was_written(struct ev_wrapper * event, struct arg_node * args) {

    char *var_watched, *var_written;
    
    var_watched = get_arg(args, 0)->arg.str;
    var_written = event->value.str;

    if (var_watched == NULL || var_written == NULL) {
        return false;
    }

    if (strcmp(var_watched, var_written) == 0) {
        return true;
    }
    else {
        return false;
    }
}


bool var_int_equals(struct ev_wrapper * event, struct arg_node * args) {

    int var_watched, compare_to;
    
    var_watched = get_arg(args, 0)->arg.i;
    compare_to = get_arg(args, 1)->arg.i;

    return (var_watched == compare_to);
}


bool var_int_less_than(struct ev_wrapper * event, struct arg_node * args) {

    int var_watched, compare_to;

    var_watched = get_arg(args, 0)->arg.i;
    compare_to = get_arg(args, 1)->arg.i;

    return (var_watched < compare_to);
}


bool var_int_greater_than(struct ev_wrapper * event, struct arg_node * args) {

    int var_watched, compare_to;
    
    var_watched = get_arg(args, 0)->arg.i;
    compare_to = get_arg(args, 1)->arg.i;

    return (var_watched > compare_to);
}


bool var_float_less_than(struct ev_wrapper * event, struct arg_node * args) {

    float var_watched, compare_to;
    
    var_watched = get_arg(args, 0)->arg.f;
    compare_to = get_arg(args, 1)->arg.f;

    return (var_watched < compare_to);
}


bool var_float_greater_than(struct ev_wrapper * event, struct arg_node * args) {

    float var_watched, compare_to;
    
    var_watched = get_arg(args, 0)->arg.f;
    compare_to = get_arg(args, 1)->arg.f;

    return (var_watched > compare_to);
}


bool var_is_true(struct ev_wrapper * event, struct arg_node * args) {

    return get_arg(args, 0)->arg.b;
}


bool var_is_false(struct ev_wrapper * event, struct arg_node * args) {

    return !(get_arg(args, 0)->arg.b);
}


bool var_str_equals(struct ev_wrapper * event, struct arg_node * args) {

    char *var_watched, *compare_to;
    
    var_watched = get_arg(args, 0)->arg.str;
    compare_to = get_arg(args, 1)->arg.str;

    if (var_watched == NULL || compare_to == NULL || (strlen(compare_to) != strlen(var_watched))) {
        return false;
    }

    return (strcmp(var_watched, compare_to) == 0);
}
