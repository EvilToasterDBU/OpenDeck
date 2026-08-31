pub(crate) mod devices;
mod misc;
mod property_inspector;
mod settings;
mod states;

use crate::{
	shared::ActionContext,
	store::profiles::{acquire_locks, get_instance},
};

use tokio_tungstenite::tungstenite::{Error, Message};
use log::warn;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "event")]
#[serde(rename_all = "camelCase")]
pub enum RegisterEvent {
	RegisterPlugin { uuid: String },
	RegisterPropertyInspector { uuid: String },
}

#[derive(Deserialize)]
pub struct ContextEvent<C = ActionContext> { pub context: C }
#[derive(Deserialize)]
pub struct PayloadEvent<T> { pub payload: T }
#[derive(Deserialize)]
pub struct ContextAndPayloadEvent<T, C = ActionContext> { pub context: C, pub payload: T }

#[derive(Deserialize)]
#[serde(tag = "event")]
#[serde(rename_all = "camelCase")]
pub enum InboundEventType {
	RegisterDevice(PayloadEvent<crate::shared::DeviceInfo>),
	UpdateDevice(PayloadEvent<crate::shared::DeviceInfo>),
	DeregisterDevice(PayloadEvent<String>),
	RerenderImages(PayloadEvent<String>),
	KeyDown(PayloadEvent<devices::PressPayload>), KeyUp(PayloadEvent<devices::PressPayload>),
	EncoderChange(PayloadEvent<devices::TicksPayload>), EncoderDown(PayloadEvent<devices::PressPayload>), EncoderUp(PayloadEvent<devices::PressPayload>),
	TouchscreenPress(PayloadEvent<devices::TouchscreenPressPayload>),
	SetSettings(ContextAndPayloadEvent<serde_json::Value>), GetSettings(ContextEvent),
	SetGlobalSettings(ContextAndPayloadEvent<serde_json::Value, String>), GetGlobalSettings(ContextEvent<String>),
	OpenUrl(PayloadEvent<misc::OpenUrlEvent>), LogMessage(PayloadEvent<misc::LogMessageEvent>),
	SetTitle(ContextAndPayloadEvent<states::SetTitlePayload>), SetImage(ContextAndPayloadEvent<states::SetImagePayload>),
	SetFeedbackLayout(ContextAndPayloadEvent<states::SetFeedbackLayoutPayload>), SetFeedback(ContextAndPayloadEvent<serde_json::Value>),
	SetState(ContextAndPayloadEvent<states::SetStatePayload>), ShowAlert(ContextEvent), ShowOk(ContextEvent),
	SendToPropertyInspector(ContextAndPayloadEvent<serde_json::Value>), SendToPlugin(ContextAndPayloadEvent<serde_json::Value>),
	SwitchProfile(misc::SwitchProfileEvent), DeviceBrightness(misc::DeviceBrightnessEvent),
}

pub async fn process_incoming_message(data: Result<Message, Error>, uuid: &str, skip_auth: bool) {
	if let Ok(Message::Text(text)) = data {
		let decoded: InboundEventType = match serde_json::from_str(&text) { Ok(event) => event, Err(error) => { if uuid.is_empty() { warn!("Failed to decode incoming event: {}", error); } else { warn!("Failed to decode incoming event from plugin {}: {}", uuid, error); } return; } };
		if !(uuid.is_empty() && skip_auth) {
			if let Some(context) = match &decoded {
				InboundEventType::SetSettings(e) => Some(&e.context), InboundEventType::GetSettings(e) => Some(&e.context), InboundEventType::SetTitle(e) => Some(&e.context),
				InboundEventType::SetImage(e) => Some(&e.context), InboundEventType::SetState(e) => Some(&e.context), InboundEventType::ShowAlert(e) => Some(&e.context),
				InboundEventType::ShowOk(e) => Some(&e.context), InboundEventType::SendToPropertyInspector(e) => Some(&e.context), _ => None,
			} {
				if let Ok(Some(instance)) = get_instance(context, &acquire_locks().await).await { if instance.action.plugin != uuid { return; } } else { return; }
			} else if let InboundEventType::SetGlobalSettings(event) = &decoded { if event.context != uuid { return; }
			} else if let InboundEventType::GetGlobalSettings(event) = &decoded { if event.context != uuid { return; }
			} else if matches!(decoded, InboundEventType::SwitchProfile(_) | InboundEventType::DeviceBrightness(_)) && uuid != "com.amansprojects.starterpack.sdPlugin" && uuid != "opendeck_alternative_elgato_implementation" { return; }
		}
		if let Err(error) = match decoded {
			InboundEventType::RegisterDevice(e) => devices::register_device(uuid, e).await,
			InboundEventType::UpdateDevice(e) => devices::update_device(uuid, e).await,
			InboundEventType::DeregisterDevice(e) => devices::deregister_device(uuid, e).await,
			InboundEventType::RerenderImages(e) => devices::rerender_images(e).await,
			InboundEventType::KeyDown(e) => devices::key_down(e).await, InboundEventType::KeyUp(e) => devices::key_up(e).await,
			InboundEventType::EncoderChange(e) => devices::encoder_change(e).await, InboundEventType::EncoderDown(e) => devices::encoder_down(e).await, InboundEventType::EncoderUp(e) => devices::encoder_up(e).await,
			InboundEventType::TouchscreenPress(e) => devices::touchscreen_press(e).await,
			InboundEventType::SetSettings(e) => settings::set_settings(e, false).await, InboundEventType::GetSettings(e) => settings::get_settings(e, false).await,
			InboundEventType::SetGlobalSettings(e) => settings::set_global_settings(e, false).await, InboundEventType::GetGlobalSettings(e) => settings::get_global_settings(e, false).await,
			InboundEventType::OpenUrl(e) => misc::open_url(e).await, InboundEventType::LogMessage(e) => misc::log_message(Some(uuid), e).await,
			InboundEventType::SetTitle(e) => states::set_title(e).await, InboundEventType::SetImage(e) => states::set_image(e).await,
			InboundEventType::SetFeedbackLayout(e) => states::set_feedback_layout(e).await, InboundEventType::SetFeedback(e) => states::set_feedback(e).await,
			InboundEventType::SetState(e) => states::set_state(e).await, InboundEventType::ShowAlert(e) => misc::show_alert(e).await, InboundEventType::ShowOk(e) => misc::show_ok(e).await,
			InboundEventType::SendToPropertyInspector(e) => property_inspector::send_to_property_inspector(e).await, InboundEventType::SendToPlugin(_) => Ok(()),
			InboundEventType::SwitchProfile(e) => misc::switch_profile(e).await, InboundEventType::DeviceBrightness(e) => misc::device_brightness(e).await,
		} && !error.to_string().contains("closed connection") { warn!("Failed to process incoming event from plugin: {}", error); }
	}
}

pub async fn process_incoming_message_pi(data: Result<Message, Error>, uuid: &str) {
	if let Ok(Message::Text(text)) = data {
		let decoded: InboundEventType = match serde_json::from_str(&text) { Ok(event) => event, Err(error) => { warn!("Failed to decode incoming event from property inspector {}: {}", uuid, error); return; } };
		if let Some(context) = match &decoded { InboundEventType::SetSettings(e) => Some(e.context.to_string()), InboundEventType::GetSettings(e) => Some(e.context.to_string()), InboundEventType::SetGlobalSettings(e) => Some(e.context.clone()), InboundEventType::GetGlobalSettings(e) => Some(e.context.clone()), InboundEventType::SendToPlugin(e) => Some(e.context.to_string()), _ => None } && context != uuid { return; }
		if let Err(error) = match decoded {
			InboundEventType::SetSettings(e) => settings::set_settings(e, true).await, InboundEventType::GetSettings(e) => settings::get_settings(e, true).await,
			InboundEventType::SetGlobalSettings(e) => settings::set_global_settings(e, true).await, InboundEventType::GetGlobalSettings(e) => settings::get_global_settings(e, true).await,
			InboundEventType::OpenUrl(e) => misc::open_url(e).await, InboundEventType::LogMessage(e) => misc::log_message(None, e).await,
			InboundEventType::SendToPlugin(e) => property_inspector::send_to_plugin(e).await, _ => Ok(())
		} && !error.to_string().contains("closed connection") { warn!("Failed to process incoming event from property inspector: {}", error); }
	}
}