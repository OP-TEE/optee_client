# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2024 The Android Open Source Project

# Enable TEE supplicant plugin support
$(call soong_config_set,optee_client,cfg_tee_supp_plugins,true)

# Enable Global Platform Sockets support
$(call soong_config_set,optee_client,cfg_gp_sockets,true)

# Enable dumping gprof data
$(call soong_config_set,optee_client,cfg_ta_gprof_support,true)

# Enable dumping ftrace data
$(call soong_config_set,optee_client,cfg_ftrace_support,true)

# Emulate RPMB
$(call soong_config_set,optee_client,rpmb_emu,true)
