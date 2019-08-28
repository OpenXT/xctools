//
// Backlight
//
// Copyright (C) 2016 - 2019 Assured Information Security, Inc. All rights reserved.
//

// ============================================================================
// Includes
// ============================================================================

#include <sys/types.h>      // open
#include <sys/stat.h>       // open
#include <fcntl.h>          // open
#include <unistd.h>         // write
#include <math.h>           // round
#include <stdbool.h>        // bool, false
#include <libudev.h>        // udev_new,
                            // udev_device_new_from_subsystem_sysname,
                            // udev_device_get_syspath,
                            // udev_device_get_sysattr_value
#include <stdlib.h>         // strtol

#include "backlight.h"
#include "project.h"
#include "xcpmd.h"

static inline uint32_t minu(uint32_t a, uint32_t b) {
    return a<b?a:b;
}
static inline float minf(float a, float b) {
    return a<b?a:b;
}
static inline uint32_t maxu(uint32_t a, uint32_t b) {
    return a>b?a:b;
}
static inline float maxf(float a, float b) {
    return a>b?a:b;
}

static uint32_t m_max = 0;
static uint32_t m_level = 0;
static struct udev *m_udev = NULL;
static struct udev_device *m_udev_device = NULL;

static const char *brightness_str = "brightness";
static const char *max_brightness_str = "max_brightness";

// ============================================================================
// Backlight Implementation
// ============================================================================

static const char * to_string(const value_t v) {

    switch (v) {
        case BRIGHTNESS:
            return brightness_str;
            break;
        case MAX_BRIGHTNESS:
            return max_brightness_str;
            break;
        default:
            xcpmd_log(LOG_ERR, "brightness to_string() failed. value %u is invalid", v);
            break;
    }

    // Shouldn't get here
    return "";
}

static uint32_t backlight_value(const value_t v) {

    uint32_t value;

    if (m_udev_device == NULL) {
        return 0;
    }

    const char *path = to_string(v);
    const char *value_str = udev_device_get_sysattr_value(m_udev_device, path);

    if (value_str == NULL || !strlen(value_str)) {
        return 0;
    }

    //intel backlight kernel interface only returns 32 bit unsigned integer
    //This truncation is harmless
    value = strtoul(value_str, NULL, 10);

    return value;
}

bool backlight_init(void) {

    m_udev=udev_new();
    if (m_udev == NULL) {
        return false;
    }

    m_udev_device=udev_device_new_from_subsystem_sysname(m_udev, "backlight", "intel_backlight");
    if (m_udev_device == NULL) {
        return false;
    }

    m_max = backlight_value(MAX_BRIGHTNESS);
    m_level = backlight_value(BRIGHTNESS);

    return true;
}

void backlight_destroy(void) {

    if (m_udev_device != NULL) {
       udev_device_unref(m_udev_device);
       m_udev = NULL;
    }
    if (m_udev != NULL) {
        udev_unref(m_udev);
        m_udev_device = NULL;
    }
}

uint32_t backlight_get(void) {

    if (m_max == 0) {
        xcpmd_log(LOG_ERR, "divide by zero error with brightness. Max is 0");
        return 100;
    }

    float tmpf = m_level * 100.f / m_max;

    return round(tmpf);
}

void backlight_set(const uint32_t level) {

    uint32_t i_level, fd;
    char levelstr[16];
    char *fullpath;
    const char *path = "/brightness";

    if (m_udev_device == NULL) {
        return;
    }
    
    const char *syspath = udev_device_get_syspath(m_udev_device);
    if (syspath == NULL || !strlen(syspath)) {
        return;
    }

    i_level = minu(level, 100u);
    i_level = maxu(i_level, 1u);
    i_level = round(i_level * m_max / 100.f);

    //max_brightness can be > 100, so allocate enough space here to hold 4+ digit integers
    snprintf(levelstr, 16, "%d", i_level);

    fullpath = malloc(strlen(syspath)+strlen(path)+1);
    if (fullpath == NULL) {
        return;
    }

    snprintf(fullpath, strlen(syspath)+strlen(path)+1, "%s%s", syspath, path);
    fd = open(fullpath, O_RDWR);

    if (fd <= 0) {
        xcpmd_log(LOG_ERR, "Failed to open: %s", fullpath);
        return;
    } else {
        size_t len1 = strlen(levelstr);
        size_t len2 = write(fd, levelstr, len1);
        if (len1 == len2) {
            m_level = level;
        }
        close(fd);
    }

    free(fullpath);
}

void backlight_increase(const uint32_t step) {

    uint32_t i_step, level;

    if (m_max == 0) {
        xcpmd_log(LOG_ERR, "divide by zero error with brightness. Max is 0");
        return;
    }

    i_step = minu(step, 100u);
    i_step = maxu(i_step, 1u);
    level = round(minf((m_level*100.f/m_max)+i_step, 100.f));

    backlight_set(level);
}

void backlight_decrease(const uint32_t step) {

    uint32_t i_step, level;

    if (m_max == 0) {
        xcpmd_log(LOG_ERR, "divide by zero error with brightness. Max is 0");
        return;
    }

    i_step = minu(step, 100u);
    i_step = maxu(i_step, 1u);
    level = round(maxf((m_level*100.f/m_max)-i_step, 1.f));

    backlight_set(level);
}
