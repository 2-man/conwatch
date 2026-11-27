use crate::event::Event;
use crate::module::{Context, Module};
use std::collections::VecDeque;

/// Dispatches events to modules; events emitted by modules are re-dispatched
/// and also returned to the caller (UI, CLI, storage).
#[derive(Default)]
pub struct Engine {
    modules: Vec<Box<dyn Module>>,
}

impl Engine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, module: Box<dyn Module>) {
        self.modules.push(module);
    }

    /// Feed events in; returns every event that passed through (inputs first,
    /// then whatever modules emitted), so callers can display/store them.
    pub fn dispatch(&mut self, input: Vec<Event>) -> Vec<Event> {
        let mut queue: VecDeque<Event> = input.into();
        let mut seen = Vec::new();
        // Guard against modules that keep emitting events forever.
        let mut budget = 10_000usize;
        while let Some(ev) = queue.pop_front() {
            for m in &mut self.modules {
                let mut ctx = Context::default();
                m.on_event(&ev, &mut ctx);
                queue.extend(ctx.out);
            }
            seen.push(ev);
            budget -= 1;
            if budget == 0 {
                break;
            }
        }
        seen
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::AlertLevel;

    struct Echo;
    impl Module for Echo {
        fn name(&self) -> &str {
            "echo"
        }
        fn on_event(&mut self, e: &Event, ctx: &mut Context) {
            if let Event::AppFirstSeen { process, .. } = e {
                ctx.alert(AlertLevel::Info, "echo", process.clone());
            }
        }
    }

    #[test]
    fn module_emitted_events_are_returned() {
        let mut eng = Engine::new();
        eng.register(Box::new(Echo));
        let out = eng.dispatch(vec![Event::AppFirstSeen { process: "a.exe".into(), exe: None }]);
        assert_eq!(out.len(), 2);
        assert!(matches!(out[1], Event::Alert(_)));
    }
}
