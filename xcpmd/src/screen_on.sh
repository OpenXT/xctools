#!/bin/bash
#
# screen_on.sh
#
# Script that powers on and remodesets a powered-off display.
#
# Copyright (c) 2015 Assured Information Security, Inc.
#
# Author:
# Jennifer Temkin <temkinj@ainfosec.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

timeout 10 vbetool dpms on
VM=$(dbus-send --system --print-reply --dest=com.citrix.xenclient.surfman / org.citrix.xenclient.surfman.get_visible | awk '/int32/ {print $2}')
dbus-send --system --dest=com.citrix.xenclient.surfman --type=method_call / org.citrix.xenclient.surfman.set_visible array:int32:0 int32:0 boolean:false
dbus-send --system --dest=com.citrix.xenclient.surfman --type=method_call / org.citrix.xenclient.surfman.set_visible array:int32:$VM int32:0 boolean:false

exit 0
