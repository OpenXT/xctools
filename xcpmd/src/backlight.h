#ifndef BACKLIGHT_H
#define BACKLIGHT_H

//
// Backlight
//
// Copyright (C) 2016 - 2019 Assured Information Security, Inc. All rights reserved.
//

// ============================================================================
// Includes
// ============================================================================

#include <stdint.h>         // uint32_t
#include <libudev.h>        // udev, udev_device
#include <stdbool.h>        // bool

// ============================================================================
// Backlight Definition
// ============================================================================

typedef enum {
    BRIGHTNESS,
    MAX_BRIGHTNESS
} value_t;

bool backlight_init(void);
void backlight_destroy(void);

uint32_t backlight_get(void);
void backlight_set(const uint32_t level);

void backlight_increase(const uint32_t step);
void backlight_decrease(const uint32_t step);

#endif // BACKLIGHT_H
