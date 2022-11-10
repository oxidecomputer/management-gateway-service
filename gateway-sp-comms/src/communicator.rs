// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use crate::error::ConfigError;
use crate::error::Error;
use crate::management_switch::ManagementSwitch;
use crate::management_switch::SwitchPort;
use crate::single_sp::AttachedSerialConsole;
use crate::single_sp::HostPhase2Provider;
use crate::single_sp::SpInventory;
use crate::Elapsed;
use crate::SpIdentifier;
use crate::SwitchConfig;
use crate::Timeout;
use futures::stream::FuturesUnordered;
use futures::Future;
use futures::Stream;
use gateway_messages::IgnitionCommand;
use gateway_messages::IgnitionState;
use gateway_messages::PowerState;
use gateway_messages::SpComponent;
use gateway_messages::SpState;
use gateway_messages::UpdateStatus;
use slog::info;
use slog::o;
use slog::Logger;
use uuid::Uuid;

/// Helper trait that allows us to return an `impl FuturesUnordered<_>` where
/// the caller can call `.is_empty()` without knowing the type of the future
/// inside the collection.
pub trait FuturesUnorderedImpl: Stream + Unpin {
    fn is_empty(&self) -> bool;
}

impl<Fut> FuturesUnorderedImpl for FuturesUnordered<Fut>
where
    Fut: Future,
{
    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

#[derive(Debug)]
pub struct Communicator {
    switch: ManagementSwitch,
}

impl Communicator {
    pub async fn new<T: HostPhase2Provider + Clone>(
        config: SwitchConfig,
        host_phase2_provider: T,
        log: &Logger,
    ) -> Result<Self, ConfigError> {
        let log = log.new(o!("component" => "SpCommunicator"));
        let switch =
            ManagementSwitch::new(config, host_phase2_provider, &log).await?;

        info!(&log, "started SP communicator");
        Ok(Self { switch })
    }

    /// Have we completed the discovery process to know how to map logical SP
    /// positions to switch ports?
    pub fn is_discovery_complete(&self) -> bool {
        self.switch.is_discovery_complete()
    }

    /// Get the name of our location.
    ///
    /// This matches one of the names specified as a possible location in the
    /// configuration we were given.
    pub fn location_name(&self) -> Result<&str, Error> {
        self.switch.location_name()
    }

    fn id_to_port(&self, sp: SpIdentifier) -> Result<SwitchPort, Error> {
        self.switch.switch_port(sp)?.ok_or(Error::SpDoesNotExist(sp))
    }

    fn port_to_id(&self, port: SwitchPort) -> Result<SpIdentifier, Error> {
        self.switch.switch_port_to_id(port)
    }

    /// Returns true if we've discovered the IP address of our local ignition
    /// controller.
    ///
    /// This method exists to be polled during test setup (to wait for discovery
    /// to happen); it should not be called outside tests.
    pub fn local_ignition_controller_address_known(&self) -> bool {
        self.switch.ignition_controller().is_some()
    }

    /// Returns true if we've discovered the IP address of the specified SP.
    ///
    /// This method exists to be polled during test setup (to wait for discovery
    /// to happen); it should not be called outside tests. In particular, it
    /// panics instead of running an error if `sp` describes an SP that isn't
    /// known to this communicator or if discovery isn't complete yet.
    pub fn address_known(&self, sp: SpIdentifier) -> bool {
        let port = self.switch.switch_port(sp).unwrap().unwrap();
        self.switch.sp(port).is_some()
    }

    /// Ask the local ignition controller for the ignition state of a given SP.
    pub async fn get_ignition_state(
        &self,
        sp: SpIdentifier,
    ) -> Result<IgnitionState, Error> {
        let controller = self
            .switch
            .ignition_controller()
            .ok_or(Error::LocalIgnitionControllerAddressUnknown)?;
        let port = self.id_to_port(sp)?;
        Ok(controller.ignition_state(port.as_ignition_target()).await?)
    }

    /// Ask the local ignition controller for the ignition state of all SPs.
    pub async fn get_ignition_state_all(
        &self,
    ) -> Result<Vec<(SpIdentifier, IgnitionState)>, Error> {
        let controller = self
            .switch
            .ignition_controller()
            .ok_or(Error::LocalIgnitionControllerAddressUnknown)?;
        let bulk_state = controller.bulk_ignition_state().await?;

        // map ignition target indices back to `SpIdentifier`s for our caller
        bulk_state
            .targets
            .iter()
            .filter(|state| {
                // TODO-cleanup `state.id` should match one of the constants
                // defined in RFD 142 section 5.2.2, all of which are nonzero.
                // What does the real ignition controller return for unpopulated
                // sleds? Our simulator returns 0 for unpopulated targets;
                // filter those out.
                state.id != 0
            })
            .copied()
            .enumerate()
            .map(|(target, state)| {
                let port = self
                    .switch
                    .switch_port_from_ignition_target(target)
                    .ok_or(Error::BadIgnitionTarget(target))?;
                let id = self.port_to_id(port)?;
                Ok((id, state))
            })
            .collect()
    }

    /// Instruct the local ignition controller to perform the given `command` on
    /// `target_sp`.
    pub async fn send_ignition_command(
        &self,
        target_sp: SpIdentifier,
        command: IgnitionCommand,
    ) -> Result<(), Error> {
        let controller = self
            .switch
            .ignition_controller()
            .ok_or(Error::LocalIgnitionControllerAddressUnknown)?;
        let target = self.id_to_port(target_sp)?.as_ignition_target();
        Ok(controller.ignition_command(target, command).await?)
    }

    /// Attach to the serial console of `sp`.
    // TODO-cleanup: This currently does not actually contact the target SP; it
    // sets up the websocket connection in the current process which knows how
    // to relay any information sent or received on that connection to the SP
    // via UDP. SPs will continuously broadcast any serial console data, even if
    // there is no attached client. Maybe this is fine, since the serial console
    // shouldn't be noisy without a corresponding client driving it?
    //
    // TODO Because this method doesn't contact the target SP, it succeeds even
    // if we don't know the IP address of that SP (yet, or possibly ever)! The
    // connection will start working if we later discover the address, but this
    // is probably not the behavior we want.
    pub async fn serial_console_attach(
        &self,
        sp: SpIdentifier,
        component: SpComponent,
    ) -> Result<AttachedSerialConsole, Error> {
        let port = self.id_to_port(sp)?;
        let sp = self.switch.sp(port).ok_or(Error::SpAddressUnknown(sp))?;
        Ok(sp.serial_console_attach(component).await?)
    }

    /// Detach any existing connection to the given SP component's serial
    /// console.
    pub async fn serial_console_detach(
        &self,
        sp: SpIdentifier,
    ) -> Result<(), Error> {
        let port = self.id_to_port(sp)?;
        let sp = self.switch.sp(port).ok_or(Error::SpAddressUnknown(sp))?;
        sp.serial_console_detach().await?;
        Ok(())
    }

    /// Get the state of a given SP.
    pub async fn get_state(&self, sp: SpIdentifier) -> Result<SpState, Error> {
        let port = self.id_to_port(sp)?;
        let sp = self.switch.sp(port).ok_or(Error::SpAddressUnknown(sp))?;
        Ok(sp.state().await?)
    }

    /// Get the inventory of a given SP.
    pub async fn inventory(
        &self,
        sp: SpIdentifier,
    ) -> Result<SpInventory, Error> {
        let port = self.id_to_port(sp)?;
        let sp = self.switch.sp(port).ok_or(Error::SpAddressUnknown(sp))?;
        Ok(sp.inventory().await?)
    }

    /// Start sending an update payload to the given SP.
    ///
    /// This function will return before the update is complete! Once the SP
    /// acknowledges that we want to apply an update, we spawn a background task
    /// to stream the update to the SP and then return. Poll the status of the
    /// update via [`Self::update_status()`].
    ///
    /// # Panics
    ///
    /// Panics if `image.is_empty()`.
    pub async fn start_update(
        &self,
        sp: SpIdentifier,
        component: SpComponent,
        update_id: Uuid,
        slot: u16,
        image: Vec<u8>,
    ) -> Result<(), Error> {
        let port = self.id_to_port(sp)?;
        let sp = self.switch.sp(port).ok_or(Error::SpAddressUnknown(sp))?;
        Ok(sp.start_update(component, update_id, slot, image).await?)
    }

    /// Get the status of an in-progress update.
    pub async fn update_status(
        &self,
        sp: SpIdentifier,
        component: SpComponent,
    ) -> Result<UpdateStatus, Error> {
        let port = self.id_to_port(sp)?;
        let sp = self.switch.sp(port).ok_or(Error::SpAddressUnknown(sp))?;
        Ok(sp.update_status(component).await?)
    }

    /// Abort an in-progress update.
    pub async fn update_abort(
        &self,
        sp: SpIdentifier,
        component: SpComponent,
        update_id: Uuid,
    ) -> Result<(), Error> {
        let port = self.id_to_port(sp)?;
        let sp = self.switch.sp(port).ok_or(Error::SpAddressUnknown(sp))?;
        Ok(sp.update_abort(component, update_id).await?)
    }

    /// Get the current (SP-controlled) power state.
    pub async fn power_state(
        &self,
        sp: SpIdentifier,
    ) -> Result<PowerState, Error> {
        let port = self.id_to_port(sp)?;
        let sp = self.switch.sp(port).ok_or(Error::SpAddressUnknown(sp))?;
        Ok(sp.power_state().await?)
    }

    /// Set the current (SP-controlled) power state.
    pub async fn set_power_state(
        &self,
        sp: SpIdentifier,
        power_state: PowerState,
    ) -> Result<(), Error> {
        let port = self.id_to_port(sp)?;
        let sp = self.switch.sp(port).ok_or(Error::SpAddressUnknown(sp))?;
        Ok(sp.set_power_state(power_state).await?)
    }

    /// Reset a given SP.
    pub async fn reset(&self, sp: SpIdentifier) -> Result<(), Error> {
        let port = self.id_to_port(sp)?;
        let sp = self.switch.sp(port).ok_or(Error::SpAddressUnknown(sp))?;
        sp.reset_prepare().await?;
        sp.reset_trigger().await?;
        Ok(())
    }

    /// Query all online SPs.
    ///
    /// `ignition_state` should be the state returned by a (recent) call to
    /// [`crate::communicator::Communicator::get_ignition_state_all()`].
    ///
    /// All SPs included in `ignition_state` will be yielded by the returned
    /// stream. The order in which they are yielded is undefined; the offline
    /// SPs are likely to be first, but even that is not guaranteed. The item
    /// yielded by offline SPs will be `None`; the item yielded by online SPs
    /// will be `Some(Ok(_))` if the future returned by `f` for that item
    /// completed before `timeout` or `Some(Err(_))` if not.
    ///
    /// Note that the timeout is be applied to each _element_ of the returned
    /// stream rather than the stream as a whole, allowing easy access to which
    /// SPs timed out based on the yielded value associated with those SPs.
    pub fn query_all_online_sps<F, T, Fut>(
        &self,
        ignition_state: &[(SpIdentifier, IgnitionState)],
        timeout: Timeout,
        f: F,
    ) -> impl FuturesUnorderedImpl<
        Item = (SpIdentifier, IgnitionState, Option<Result<T, Elapsed>>),
    >
    where
        F: FnMut(SpIdentifier) -> Fut + Clone,
        Fut: Future<Output = T>,
    {
        ignition_state
            .iter()
            .copied()
            .map(move |(id, state)| {
                let mut f = f.clone();
                async move {
                    let val = if state.is_powered_on() {
                        Some(timeout.timeout_at(f(id)).await)
                    } else {
                        None
                    };
                    (id, state, val)
                }
            })
            .collect::<FuturesUnordered<_>>()
    }
}
