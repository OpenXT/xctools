/*
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

#ifndef __DB_EVENTS_MODULES_H__
#define __DB_EVENTS_MODULES_H__

#define EVENT_VAR_WRITTEN      0
#define EVENT_VAR_WRITTEN_EDGE 1

//Names required for dynamic loading
#define DB_EVENTS_MODULE_SONAME   "db-events-module.so"
#define DB_EVENTS                 "_db_event_table"

#endif
