/*
 * Copyright (c) 2016 Linaro Limited.
 * Copyright (c) 2014-2016 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef __KIRIN_DRM_DRV_H__
#define __KIRIN_DRM_DRV_H__

#include <drm/drmP.h>
#include <../../drivers/staging/android/ion/ion.h>
//#include <linux/hisi/hisi_ion.h>
//#include <linux/hisi/hisi-iommu.h>
#include <linux/iommu.h>

#include "drm_crtc.h"
#include "drm_fb_helper.h"

#define MAX_CRTC	2

enum kirin_drm_chip{
	DRM_KIRIN620,
	DRM_KIRIN960,
};

/* display controller init/cleanup ops */
struct kirin_dc_ops {
	int (*init)(struct platform_device *pdev);
	void (*cleanup)(struct platform_device *pdev);
};


#ifdef CONFIG_DRM_HISI_KIRIN960
struct kirin_drm_private {
	struct drm_fb_helper *fb_helper;
	struct drm_fbdev_cma *fbdev;
	struct drm_crtc *crtc[MAX_CRTC];
};

extern void dsi_set_output_client(struct drm_device *dev);
#else
struct kirin_drm_private {
	struct drm_fbdev_cma *fbdev;
};

#endif

/*for kirin620*/
int ade_drm_init(struct platform_device *pdev);
void ade_drm_cleanup(struct platform_device *pdev);
void kirin_drm_mode_config_init_size(struct drm_device *dev);
/*end*/
/*for kirin960*/
int dss_drm_init(struct platform_device *pdev);
void dss_drm_cleanup(struct platform_device *pdev);
void kirin960_drm_mode_config_init_size(struct drm_device *dev);
int kirin_drm_connectors_register(struct drm_device *dev);
/*end*/

#endif /* __KIRIN_DRM_DRV_H__ */
