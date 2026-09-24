# Must match TA_RA_DEMO_UUID in include/ra_demo_ta.h (same UUID, dashed
# string form vs. struct form). If you regenerate the UUID, update both.
BINARY = bb9a73d7-684b-4785-9e39-06bfaab9a2ef

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk),)
clean:
	@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
	@echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
