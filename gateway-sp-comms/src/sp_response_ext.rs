// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::error::CommunicationError;
use gateway_messages::ignition::LinkEvents;
use gateway_messages::DiscoverResponse;
use gateway_messages::IgnitionState;
use gateway_messages::PowerState;
use gateway_messages::SpResponse;
use gateway_messages::SpState;
use gateway_messages::StartupOptions;
use gateway_messages::TlvPage;
use gateway_messages::UpdateStatus;

type Result<T> = std::result::Result<T, CommunicationError>;

// When we send a request we expect a specific kind of response; the boilerplate
// for confirming that is a little noisy, so it lives in this extension trait.
pub(crate) trait SpResponseExt {
    fn name(&self) -> &'static str;

    fn expect_discover(self) -> Result<DiscoverResponse>;

    fn expect_ignition_state(self) -> Result<IgnitionState>;

    fn expect_bulk_ignition_state(self) -> Result<TlvPage>;

    fn expect_ignition_link_events(self) -> Result<LinkEvents>;

    fn expect_bulk_ignition_link_events(self) -> Result<TlvPage>;

    fn expect_ignition_command_ack(self) -> Result<()>;

    fn expect_clear_ignition_link_events_ack(self) -> Result<()>;

    fn expect_sp_state(self) -> Result<SpState>;

    fn expect_serial_console_attach_ack(self) -> Result<()>;

    fn expect_serial_console_write_ack(self) -> Result<u64>;

    fn expect_serial_console_detach_ack(self) -> Result<()>;

    fn expect_serial_console_keepalive_ack(self) -> Result<()>;

    fn expect_serial_console_break_ack(self) -> Result<()>;

    fn expect_sp_update_prepare_ack(self) -> Result<()>;

    fn expect_component_update_prepare_ack(self) -> Result<()>;

    fn expect_update_status(self) -> Result<UpdateStatus>;

    fn expect_update_chunk_ack(self) -> Result<()>;

    fn expect_update_abort_ack(self) -> Result<()>;

    fn expect_power_state(self) -> Result<PowerState>;

    fn expect_set_power_state_ack(self) -> Result<()>;

    fn expect_sys_reset_prepare_ack(self) -> Result<()>;

    fn expect_inventory(self) -> Result<TlvPage>;

    fn expect_startup_options(self) -> Result<StartupOptions>;

    fn expect_set_startup_options_ack(self) -> Result<()>;

    fn expect_component_details(self) -> Result<TlvPage>;

    fn expect_component_clear_status_ack(self) -> Result<()>;

    fn expect_component_active_slot(self) -> Result<u16>;

    fn expect_component_set_active_slot_ack(self) -> Result<()>;

    fn expect_component_set_and_persist_active_slot_ack(self) -> Result<()>;

    fn expect_send_host_nmi_ack(self) -> Result<()>;

    fn expect_set_ipcc_key_lookup_value_ack(self) -> Result<()>;

    fn expect_caboose_value(self) -> Result<()>;

    fn expect_sys_reset_component_prepare_ack(self) -> Result<()>;

    fn expect_sys_reset_component_trigger_ack(self) -> Result<()>;

    fn expect_switch_default_image_ack(self) -> Result<()>;
}

impl SpResponseExt for SpResponse {
    fn name(&self) -> &'static str {
        match self {
            Self::Discover(_) => response_kind_names::DISCOVER,
            Self::IgnitionState(_) => response_kind_names::IGNITION_STATE,
            Self::IgnitionLinkEvents(_) => {
                response_kind_names::IGNITION_LINK_EVENTS
            }
            Self::BulkIgnitionState(_) => {
                response_kind_names::BULK_IGNITION_STATE
            }
            Self::BulkIgnitionLinkEvents(_) => {
                response_kind_names::BULK_IGNITION_LINK_EVENTS
            }
            Self::IgnitionCommandAck => {
                response_kind_names::IGNITION_COMMAND_ACK
            }
            Self::ClearIgnitionLinkEventsAck => {
                response_kind_names::CLEAR_IGNITION_LINK_EVENTS_ACK
            }
            Self::SpState(_) => response_kind_names::SP_STATE,
            Self::SerialConsoleAttachAck => {
                response_kind_names::SERIAL_CONSOLE_ATTACH_ACK
            }
            Self::SerialConsoleWriteAck { .. } => {
                response_kind_names::SERIAL_CONSOLE_WRITE_ACK
            }
            Self::SerialConsoleDetachAck => {
                response_kind_names::SERIAL_CONSOLE_DETACH_ACK
            }
            Self::SerialConsoleKeepAliveAck => {
                response_kind_names::SERIAL_CONSOLE_KEEPALIVE_ACK
            }
            Self::SerialConsoleBreakAck => {
                response_kind_names::SERIAL_CONSOLE_BREAK_ACK
            }
            Self::SpUpdatePrepareAck => {
                response_kind_names::SP_UPDATE_PREPARE_ACK
            }
            Self::ComponentUpdatePrepareAck => {
                response_kind_names::COMPONENT_UPDATE_PREPARE_ACK
            }
            Self::UpdateStatus(_) => response_kind_names::UPDATE_STATUS,
            Self::UpdateAbortAck => response_kind_names::UPDATE_ABORT_ACK,
            Self::UpdateChunkAck => response_kind_names::UPDATE_CHUNK_ACK,
            Self::PowerState(_) => response_kind_names::POWER_STATE,
            Self::SetPowerStateAck => response_kind_names::SET_POWER_STATE_ACK,
            Self::ResetPrepareAck => response_kind_names::RESET_PREPARE_ACK,
            Self::Inventory(_) => response_kind_names::INVENTORY,
            Self::Error(_) => response_kind_names::ERROR,
            Self::StartupOptions(_) => response_kind_names::STARTUP_OPTIONS,
            Self::SetStartupOptionsAck => {
                response_kind_names::SET_STARTUP_OPTIONS_ACK
            }
            Self::ComponentDetails(_) => response_kind_names::COMPONENT_DETAILS,
            Self::ComponentClearStatusAck => {
                response_kind_names::COMPONENT_CLEAR_STATUS_ACK
            }
            Self::ComponentActiveSlot(_) => {
                response_kind_names::COMPONENT_ACTIVE_SLOT
            }
            Self::ComponentSetActiveSlotAck => {
                response_kind_names::COMPONENT_SET_ACTIVE_SLOT_ACK
            }
            Self::ComponentSetAndPersistActiveSlotAck => {
                response_kind_names::COMPONENT_SET_AND_PERSIST_ACTIVE_SLOT_ACK
            }
            Self::SendHostNmiAck => response_kind_names::SEND_HOST_NMI_ACK,
            Self::SetIpccKeyLookupValueAck => {
                response_kind_names::SET_IPCC_KEY_LOOKUP_VALUE_ACK
            }
            Self::CabooseValue => response_kind_names::CABOOSE_VALUE,
            Self::ResetComponentPrepareAck => {
                response_kind_names::RESET_COMPONENT_PREPARE_ACK
            }
            Self::ResetComponentTriggerAck => {
                response_kind_names::RESET_COMPONENT_TRIGGER_ACK
            }
            Self::SwitchDefaultImageAck => {
                response_kind_names::SWITCH_DEFAULT_IMAGE_ACK
            }
        }
    }

    fn expect_discover(self) -> Result<DiscoverResponse> {
        match self {
            Self::Discover(discover) => Ok(discover),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::DISCOVER,
                got: other.name(),
            }),
        }
    }

    fn expect_ignition_state(self) -> Result<IgnitionState> {
        match self {
            Self::IgnitionState(state) => Ok(state),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::IGNITION_STATE,
                got: other.name(),
            }),
        }
    }

    fn expect_bulk_ignition_state(self) -> Result<TlvPage> {
        match self {
            Self::BulkIgnitionState(page) => Ok(page),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::BULK_IGNITION_STATE,
                got: other.name(),
            }),
        }
    }

    fn expect_ignition_link_events(self) -> Result<LinkEvents> {
        match self {
            Self::IgnitionLinkEvents(events) => Ok(events),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::IGNITION_LINK_EVENTS,
                got: other.name(),
            }),
        }
    }

    fn expect_bulk_ignition_link_events(self) -> Result<TlvPage> {
        match self {
            Self::BulkIgnitionLinkEvents(page) => Ok(page),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::BULK_IGNITION_LINK_EVENTS,
                got: other.name(),
            }),
        }
    }

    fn expect_ignition_command_ack(self) -> Result<()> {
        match self {
            Self::IgnitionCommandAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::IGNITION_COMMAND_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_clear_ignition_link_events_ack(self) -> Result<()> {
        match self {
            Self::ClearIgnitionLinkEventsAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::CLEAR_IGNITION_LINK_EVENTS_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_sp_state(self) -> Result<SpState> {
        match self {
            Self::SpState(state) => Ok(state),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::SP_STATE,
                got: other.name(),
            }),
        }
    }

    fn expect_serial_console_attach_ack(self) -> Result<()> {
        match self {
            Self::SerialConsoleAttachAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::SERIAL_CONSOLE_ATTACH_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_serial_console_write_ack(self) -> Result<u64> {
        match self {
            Self::SerialConsoleWriteAck { furthest_ingested_offset } => {
                Ok(furthest_ingested_offset)
            }
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::SERIAL_CONSOLE_WRITE_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_serial_console_detach_ack(self) -> Result<()> {
        match self {
            Self::SerialConsoleDetachAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::SERIAL_CONSOLE_DETACH_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_serial_console_keepalive_ack(self) -> Result<()> {
        match self {
            Self::SerialConsoleKeepAliveAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::SERIAL_CONSOLE_KEEPALIVE_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_serial_console_break_ack(self) -> Result<()> {
        match self {
            Self::SerialConsoleBreakAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::SERIAL_CONSOLE_BREAK_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_sp_update_prepare_ack(self) -> Result<()> {
        match self {
            Self::SpUpdatePrepareAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::SP_UPDATE_PREPARE_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_component_update_prepare_ack(self) -> Result<()> {
        match self {
            Self::ComponentUpdatePrepareAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::COMPONENT_UPDATE_PREPARE_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_update_status(self) -> Result<UpdateStatus> {
        match self {
            Self::UpdateStatus(status) => Ok(status),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::UPDATE_STATUS,
                got: other.name(),
            }),
        }
    }

    fn expect_update_chunk_ack(self) -> Result<()> {
        match self {
            Self::UpdateChunkAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::UPDATE_CHUNK_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_update_abort_ack(self) -> Result<()> {
        match self {
            Self::UpdateAbortAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::UPDATE_ABORT_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_power_state(self) -> Result<PowerState> {
        match self {
            Self::PowerState(power_state) => Ok(power_state),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::POWER_STATE,
                got: other.name(),
            }),
        }
    }

    fn expect_set_power_state_ack(self) -> Result<()> {
        match self {
            Self::SetPowerStateAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::SET_POWER_STATE_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_sys_reset_prepare_ack(self) -> Result<()> {
        match self {
            Self::ResetPrepareAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::RESET_PREPARE_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_inventory(self) -> Result<TlvPage> {
        match self {
            Self::Inventory(page) => Ok(page),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::INVENTORY,
                got: other.name(),
            }),
        }
    }

    fn expect_startup_options(self) -> Result<StartupOptions> {
        match self {
            Self::StartupOptions(options) => Ok(options),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::STARTUP_OPTIONS,
                got: other.name(),
            }),
        }
    }

    fn expect_set_startup_options_ack(self) -> Result<()> {
        match self {
            Self::SetStartupOptionsAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::SET_STARTUP_OPTIONS_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_component_details(self) -> Result<TlvPage> {
        match self {
            Self::ComponentDetails(page) => Ok(page),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::COMPONENT_DETAILS,
                got: other.name(),
            }),
        }
    }

    fn expect_component_clear_status_ack(self) -> Result<()> {
        match self {
            Self::ComponentClearStatusAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::COMPONENT_CLEAR_STATUS_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_component_active_slot(self) -> Result<u16> {
        match self {
            Self::ComponentActiveSlot(slot) => Ok(slot),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::COMPONENT_ACTIVE_SLOT,
                got: other.name(),
            }),
        }
    }

    fn expect_component_set_active_slot_ack(self) -> Result<()> {
        match self {
            Self::ComponentSetActiveSlotAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::COMPONENT_SET_ACTIVE_SLOT_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_component_set_and_persist_active_slot_ack(self) -> Result<()> {
        match self {
            Self::ComponentSetAndPersistActiveSlotAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::COMPONENT_SET_AND_PERSIST_ACTIVE_SLOT_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_send_host_nmi_ack(self) -> Result<()> {
        match self {
            Self::SendHostNmiAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::SEND_HOST_NMI_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_set_ipcc_key_lookup_value_ack(self) -> Result<()> {
        match self {
            Self::SetIpccKeyLookupValueAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::SET_IPCC_KEY_LOOKUP_VALUE_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_caboose_value(self) -> Result<()> {
        match self {
            Self::CabooseValue => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::CABOOSE_VALUE,
                got: other.name(),
            }),
        }
    }

    fn expect_sys_reset_component_prepare_ack(self) -> Result<()> {
        match self {
            Self::ResetComponentPrepareAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::RESET_COMPONENT_PREPARE_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_sys_reset_component_trigger_ack(self) -> Result<()> {
        match self {
            Self::ResetComponentTriggerAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::RESET_COMPONENT_TRIGGER_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_switch_default_image_ack(self) -> Result<()> {
        match self {
            Self::SwitchDefaultImageAck => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: response_kind_names::SWITCH_DEFAULT_IMAGE_ACK,
                got: other.name(),
            }),
        }
    }
}

mod response_kind_names {
    pub(super) const DISCOVER: &str = "discover";
    pub(super) const IGNITION_STATE: &str = "ignition_state";
    pub(super) const BULK_IGNITION_STATE: &str = "bulk_ignition_state";
    pub(super) const IGNITION_LINK_EVENTS: &str = "ignition_link_events";
    pub(super) const BULK_IGNITION_LINK_EVENTS: &str =
        "bulk_ignition_link_events";
    pub(super) const IGNITION_COMMAND_ACK: &str = "ignition_command_ack";
    pub(super) const CLEAR_IGNITION_LINK_EVENTS_ACK: &str =
        "clear_ignition_link_events_ack";
    pub(super) const SP_STATE: &str = "sp_state";
    pub(super) const SERIAL_CONSOLE_ATTACH_ACK: &str =
        "serial_console_attach_ack";
    pub(super) const SERIAL_CONSOLE_WRITE_ACK: &str =
        "serial_console_write_ack";
    pub(super) const SERIAL_CONSOLE_DETACH_ACK: &str =
        "serial_console_detach_ack";
    pub(super) const SERIAL_CONSOLE_KEEPALIVE_ACK: &str =
        "serial_console_keepalive_ack";
    pub(super) const SERIAL_CONSOLE_BREAK_ACK: &str =
        "serial_console_break_ack";
    pub(super) const SP_UPDATE_PREPARE_ACK: &str = "sp_update_prepare_ack";
    pub(super) const COMPONENT_UPDATE_PREPARE_ACK: &str =
        "component_update_prepare_ack";
    pub(super) const UPDATE_STATUS: &str = "update_status";
    pub(super) const UPDATE_ABORT_ACK: &str = "update_abort_ack";
    pub(super) const UPDATE_CHUNK_ACK: &str = "update_chunk_ack";
    pub(super) const POWER_STATE: &str = "power_state";
    pub(super) const SET_POWER_STATE_ACK: &str = "set_power_state_ack";
    pub(super) const RESET_PREPARE_ACK: &str = "reset_prepare_ack";
    pub(super) const INVENTORY: &str = "inventory";
    pub(super) const ERROR: &str = "error";
    pub(super) const STARTUP_OPTIONS: &str = "startup_options";
    pub(super) const SET_STARTUP_OPTIONS_ACK: &str = "set_startup_options_ack";
    pub(super) const COMPONENT_DETAILS: &str = "component_details";
    pub(super) const COMPONENT_CLEAR_STATUS_ACK: &str =
        "component_clear_status_ack";
    pub(super) const COMPONENT_ACTIVE_SLOT: &str = "component_active_slot";
    pub(super) const COMPONENT_SET_ACTIVE_SLOT_ACK: &str =
        "component_set_active_slot_ack";
    pub(super) const COMPONENT_SET_AND_PERSIST_ACTIVE_SLOT_ACK: &str =
        "component_set_and_persist_active_slot_ack";
    pub(super) const SEND_HOST_NMI_ACK: &str = "send_host_nmi_ack";
    pub(super) const SET_IPCC_KEY_LOOKUP_VALUE_ACK: &str =
        "set_ipcc_key_lookup_value_ack";
    pub(super) const CABOOSE_VALUE: &str = "caboose_value";
    pub(super) const RESET_COMPONENT_PREPARE_ACK: &str =
        "reset_component_prepare_ack";
    pub(super) const RESET_COMPONENT_TRIGGER_ACK: &str =
        "reset_component_trigger_ack";
    pub(super) const SWITCH_DEFAULT_IMAGE_ACK: &str =
        "switch_default_image_ack";
}
