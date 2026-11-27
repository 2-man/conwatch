use crate::event::{Alert, AlertLevel, Event};

/// Handle given to modules to emit follow-up events.
#[derive(Default)]
pub struct Context {
    pub(crate) out: Vec<Event>,
}

impl Context {
    pub fn emit(&mut self, event: Event) {
        self.out.push(event);
    }

    pub fn alert(&mut self, level: AlertLevel, source: &str, message: impl Into<String>) {
        self.emit(Event::Alert(Alert {
            level,
            source: source.to_string(),
            message: message.into(),
        }));
    }
}

/// A ConWatch module. Built-in modules implement this directly; external
/// (user) modules will be wrapped by a process-based adapter implementing
/// the same trait.
pub trait Module: Send {
    fn name(&self) -> &str;
    fn on_event(&mut self, event: &Event, ctx: &mut Context);
}
