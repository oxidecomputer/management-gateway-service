// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::error::SpCommunicationError;
use gateway_messages::DiscoverResponse;
use gateway_messages::IgnitionState;
use gateway_messages::PowerState;
use gateway_messages::SpResponse;
use gateway_messages::SpState;
use gateway_messages::StartupOptions;
use gateway_messages::TlvPage;
use gateway_messages::UpdateStatus;

// When we send a request we expect a specific kind of response; the boilerplate
// for confirming that is a little noisy, so it lives in this extension trait.
pub(crate) trait SpResponseExt {
    fn name(&self) -> &'static str;

    fn expect_discover(self) -> Result<DiscoverResponse, SpCommunicationError>;

    fn expect_ignition_state(
        self,
    ) -> Result<IgnitionState, SpCommunicationError>;

    fn expect_bulk_ignition_state(
        self,
    ) -> Result<TlvPage, SpCommunicationError>;

    fn expect_ignition_command_ack(self) -> Result<(), SpCommunicationError>;

    fn expect_sp_state(self) -> Result<SpState, SpCommunicationError>;

    fn expect_serial_console_attach_ack(
        self,
    ) -> Result<(), SpCommunicationError>;

    fn expect_serial_console_write_ack(
        self,
    ) -> Result<u64, SpCommunicationError>;

    fn expect_serial_console_detach_ack(
        self,
    ) -> Result<(), SpCommunicationError>;

    fn expect_sp_update_prepare_ack(self) -> Result<(), SpCommunicationError>;

    fn expect_component_update_prepare_ack(
        self,
    ) -> Result<(), SpCommunicationError>;

    fn expect_update_status(self)
        -> Result<UpdateStatus, SpCommunicationError>;

    fn expect_update_chunk_ack(self) -> Result<(), SpCommunicationError>;

    fn expect_update_abort_ack(self) -> Result<(), SpCommunicationError>;

    fn expect_power_state(self) -> Result<PowerState, SpCommunicationError>;

    fn expect_set_power_state_ack(self) -> Result<(), SpCommunicationError>;

    fn expect_sys_reset_prepare_ack(self) -> Result<(), SpCommunicationError>;

    fn expect_inventory(self) -> Result<TlvPage, SpCommunicationError>;

    fn expect_startup_options(
        self,
    ) -> Result<StartupOptions, SpCommunicationError>;

    fn expect_set_startup_options_ack(self)
        -> Result<(), SpCommunicationError>;

    fn expect_component_details(self) -> Result<TlvPage, SpCommunicationError>;
}

impl SpResponseExt for SpResponse {
    fn name(&self) -> &'static str {
        match self {
            Self::Discover(_) => response_kind_names::DISCOVER,
            Self::IgnitionState(_) => response_kind_names::IGNITION_STATE,
            Self::BulkIgnitionState(_) => {
                response_kind_names::BULK_IGNITION_STATE
            }
            Self::IgnitionCommandAck => {
                response_kind_names::IGNITION_COMMAND_ACK
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
        }
    }

    fn expect_discover(self) -> Result<DiscoverResponse, SpCommunicationError> {
        match self {
            Self::Discover(discover) => Ok(discover),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::DISCOVER,
                got: other.name(),
            }),
        }
    }

    fn expect_ignition_state(
        self,
    ) -> Result<IgnitionState, SpCommunicationError> {
        match self {
            Self::IgnitionState(state) => Ok(state),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::IGNITION_STATE,
                got: other.name(),
            }),
        }
    }

    fn expect_bulk_ignition_state(
        self,
    ) -> Result<TlvPage, SpCommunicationError> {
        match self {
            Self::BulkIgnitionState(page) => Ok(page),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::BULK_IGNITION_STATE,
                got: other.name(),
            }),
        }
    }

    fn expect_ignition_command_ack(self) -> Result<(), SpCommunicationError> {
        match self {
            Self::IgnitionCommandAck => Ok(()),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::IGNITION_COMMAND_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_sp_state(self) -> Result<SpState, SpCommunicationError> {
        match self {
            Self::SpState(state) => Ok(state),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::SP_STATE,
                got: other.name(),
            }),
        }
    }

    fn expect_serial_console_attach_ack(
        self,
    ) -> Result<(), SpCommunicationError> {
        match self {
            Self::SerialConsoleAttachAck => Ok(()),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::SP_STATE,
                got: other.name(),
            }),
        }
    }

    fn expect_serial_console_write_ack(
        self,
    ) -> Result<u64, SpCommunicationError> {
        match self {
            Self::SerialConsoleWriteAck { furthest_ingested_offset } => {
                Ok(furthest_ingested_offset)
            }
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::SP_STATE,
                got: other.name(),
            }),
        }
    }

    fn expect_serial_console_detach_ack(
        self,
    ) -> Result<(), SpCommunicationError> {
        match self {
            Self::SerialConsoleDetachAck => Ok(()),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::SP_STATE,
                got: other.name(),
            }),
        }
    }

    fn expect_sp_update_prepare_ack(self) -> Result<(), SpCommunicationError> {
        match self {
            Self::SpUpdatePrepareAck => Ok(()),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::SP_UPDATE_PREPARE_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_component_update_prepare_ack(
        self,
    ) -> Result<(), SpCommunicationError> {
        match self {
            Self::ComponentUpdatePrepareAck => Ok(()),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::COMPONENT_UPDATE_PREPARE_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_update_status(
        self,
    ) -> Result<UpdateStatus, SpCommunicationError> {
        match self {
            Self::UpdateStatus(status) => Ok(status),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::UPDATE_STATUS,
                got: other.name(),
            }),
        }
    }

    fn expect_update_chunk_ack(self) -> Result<(), SpCommunicationError> {
        match self {
            Self::UpdateChunkAck => Ok(()),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::UPDATE_CHUNK_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_update_abort_ack(self) -> Result<(), SpCommunicationError> {
        match self {
            Self::UpdateAbortAck => Ok(()),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::UPDATE_ABORT_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_power_state(self) -> Result<PowerState, SpCommunicationError> {
        match self {
            Self::PowerState(power_state) => Ok(power_state),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::POWER_STATE,
                got: other.name(),
            }),
        }
    }

    fn expect_set_power_state_ack(self) -> Result<(), SpCommunicationError> {
        match self {
            Self::SetPowerStateAck => Ok(()),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::SET_POWER_STATE_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_sys_reset_prepare_ack(self) -> Result<(), SpCommunicationError> {
        match self {
            Self::ResetPrepareAck => Ok(()),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::RESET_PREPARE_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_inventory(self) -> Result<TlvPage, SpCommunicationError> {
        match self {
            Self::Inventory(page) => Ok(page),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::INVENTORY,
                got: other.name(),
            }),
        }
    }

    fn expect_startup_options(
        self,
    ) -> Result<StartupOptions, SpCommunicationError> {
        match self {
            Self::StartupOptions(options) => Ok(options),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::STARTUP_OPTIONS,
                got: other.name(),
            }),
        }
    }

    fn expect_set_startup_options_ack(
        self,
    ) -> Result<(), SpCommunicationError> {
        match self {
            Self::SetStartupOptionsAck => Ok(()),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::SET_STARTUP_OPTIONS_ACK,
                got: other.name(),
            }),
        }
    }

    fn expect_component_details(self) -> Result<TlvPage, SpCommunicationError> {
        match self {
            Self::ComponentDetails(page) => Ok(page),
            Self::Error(err) => Err(SpCommunicationError::SpError(err)),
            other => Err(SpCommunicationError::BadResponseType {
                expected: response_kind_names::COMPONENT_DETAILS,
                got: other.name(),
            }),
        }
    }
}

mod response_kind_names {
    pub(super) const DISCOVER: &str = "discover";
    pub(super) const IGNITION_STATE: &str = "ignition_state";
    pub(super) const BULK_IGNITION_STATE: &str = "bulk_ignition_state";
    pub(super) const IGNITION_COMMAND_ACK: &str = "ignition_command_ack";
    pub(super) const SP_STATE: &str = "sp_state";
    pub(super) const SERIAL_CONSOLE_ATTACH_ACK: &str =
        "serial_console_attach_ack";
    pub(super) const SERIAL_CONSOLE_WRITE_ACK: &str =
        "serial_console_write_ack";
    pub(super) const SERIAL_CONSOLE_DETACH_ACK: &str =
        "serial_console_detach_ack";
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
}
