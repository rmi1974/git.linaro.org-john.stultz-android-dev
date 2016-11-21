/**
 * This header provides index for the reset controller
 * based on hi6220 SoC.
 */
#ifndef _DT_BINDINGS_RESET_CONTROLLER_HI6220
#define _DT_BINDINGS_RESET_CONTROLLER_HI6220


/* reset in sysctrl */
#define PERIPH_RSTDIS0_MMC0             0
#define PERIPH_RSTDIS0_MMC1             1
#define PERIPH_RSTDIS0_MMC2             2
#define PERIPH_RSTDIS0_NANDC            3
#define PERIPH_RSTDIS0_USBOTG_BUS       4
#define PERIPH_RSTDIS0_POR_PICOPHY      5
#define PERIPH_RSTDIS0_USBOTG           6
#define PERIPH_RSTDIS0_USBOTG_32K       7
#define PERIPH_RSTDIS1_HIFI             8
#define PERIPH_RSTDIS1_DIGACODEC        9
#define PERIPH_RSTEN2_IPF               10
#define PERIPH_RSTEN2_SOCP              11
#define PERIPH_RSTEN2_DMAC              12
#define PERIPH_RSTEN2_SECENG            13
#define PERIPH_RSTEN2_ABB               14
#define PERIPH_RSTEN2_HPM0              15
#define PERIPH_RSTEN2_HPM1              16
#define PERIPH_RSTEN2_HPM2              17
#define PERIPH_RSTEN2_HPM3              18
#define PERIPH_RSTEN3_CSSYS             19
#define PERIPH_RSTEN3_I2C0              20
#define PERIPH_RSTEN3_I2C1              21
#define PERIPH_RSTEN3_I2C2              22
#define PERIPH_RSTEN3_I2C3              23
#define PERIPH_RSTEN3_UART1             24
#define PERIPH_RSTEN3_UART2             25
#define PERIPH_RSTEN3_UART3             26
#define PERIPH_RSTEN3_UART4             27
#define PERIPH_RSTEN3_SSP               28
#define PERIPH_RSTEN3_PWM               29
#define PERIPH_RSTEN3_BLPWM             30
#define PERIPH_RSTEN3_TSENSOR           31
#define PERIPH_RSTEN3_DAPB              32
#define PERIPH_RSTEN3_HKADC             33
#define PERIPH_RSTEN3_CODEC_SSI         34
#define PERIPH_RSTEN8_RS0               35
#define PERIPH_RSTEN8_RS2               36
#define PERIPH_RSTEN8_RS3               37
#define PERIPH_RSTEN8_MS0               38
#define PERIPH_RSTEN8_MS2               39
#define PERIPH_RSTEN8_XG2RAM0           40
#define PERIPH_RSTEN8_X2SRAM_TZMA       41
#define PERIPH_RSTEN8_SRAM              42
#define PERIPH_RSTEN8_HARQ              43
#define PERIPH_RSTEN8_DDRC              44
#define PERIPH_RSTEN8_DDRC_APB          45
#define PERIPH_RSTEN8_DDRPACK_APB       46
#define PERIPH_RSTEN8_DDRT              47
#define PERIPH_RSDIST9_CARM_DAP         48
#define PERIPH_RSDIST9_CARM_ATB         49
#define PERIPH_RSDIST9_CARM_LBUS        50
#define PERIPH_RSDIST9_CARM_POR         51
#define PERIPH_RSDIST9_CARM_CORE        52
#define PERIPH_RSDIST9_CARM_DBG         53
#define PERIPH_RSDIST9_CARM_L2          54
#define PERIPH_RSDIST9_CARM_SOCDBG      55
#define PERIPH_RSDIST9_CARM_ETM         56

/* reset in media */
#define MEDIA_G3D                       0
#define MEDIA_CODEC_VPU                 1
#define MEDIA_CODEC_JPEG                2
#define MEDIA_ISP                       3
#define MEDIA_ADE                       4
#define MEDIA_MMU                       5
#define MEDIA_XG2RAM1                   6

#endif /*_DT_BINDINGS_RESET_CONTROLLER_HI6220*/
