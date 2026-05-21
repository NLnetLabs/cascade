use std::{collections::HashMap, ops::ControlFlow, time::Duration};

use ansi_to_tui::IntoText as _;
use cascade_api::{
    PolicyInfo, PolicyInfoError, PolicyListResult, ZoneName, ZoneStatus, ZoneStatusError,
    ZonesListResult,
};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::{
        self,
        event::{KeyCode, KeyModifiers},
    },
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span, Text},
    widgets::{Block, Clear, List, ListDirection, ListState, Padding, Paragraph, Tabs},
};
use tokio::sync::oneshot;

use crate::client::CascadeApiClient;

/// The whole state of the TUI
#[derive(Default)]
struct State {
    tab: Tab,
    zones: Zones,
    policies: Policies,
}

#[derive(Default)]
struct Zones {
    list: Fetch<Vec<ZoneName>>,
    status: HashMap<ZoneName, Fetch<(ZoneStatus, PolicyInfo)>>,
    state: ListState,
}

#[derive(Default)]
struct Policies {
    list: Fetch<Vec<String>>,
    info: HashMap<String, Fetch<PolicyInfo>>,
    state: ListState,
}

/// The different tabs that we have in the TUI
#[repr(u32)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Tab {
    #[default]
    Zones = 0,
    Policies = 1,
    _Config = 2,
}

/// A bit of information that needs to be fetched via the HTTP API
#[derive(Default)]
enum Fetch<T> {
    /// This information has not been requested yet
    #[default]
    Unrequested,
    Pending(oneshot::Receiver<Result<T, String>>),
    Done(Result<T, String>),
}

impl<T: Send + 'static> Fetch<T> {
    fn get_or_fetch(
        &mut self,
        f: impl (FnOnce() -> Result<T, String>) + Send + 'static,
    ) -> Option<&mut Result<T, String>> {
        match self {
            Self::Unrequested => {
                let (tx, rx) = oneshot::channel();
                std::thread::spawn(|| {
                    let res = f();
                    tx.send(res).map_err(|_| ()).unwrap();
                });
                *self = Self::Pending(rx);
                None
            }
            Self::Pending(r) => {
                if let Ok(v) = r.try_recv() {
                    *self = Self::Done(v);
                }
                let Self::Done(v) = self else {
                    return None;
                };
                Some(v)
            }
            Self::Done(v) => Some(v),
        }
    }

    fn reset(&mut self) {
        *self = Self::Unrequested;
    }
}

pub fn launch(client: CascadeApiClient) -> Result<(), String> {
    ratatui::run(|terminal| app(client, terminal)).map_err(|e| e.to_string())
}

fn app(client: CascadeApiClient, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
    let mut state = State::default();
    loop {
        terminal.draw(|frame| render(&mut state, &client, frame))?;
        match handle_events(&mut state) {
            ControlFlow::Continue(()) => {}
            ControlFlow::Break(r) => return r,
        }
    }
}

fn handle_events(state: &mut State) -> ControlFlow<Result<(), std::io::Error>> {
    let has_event = match crossterm::event::poll(Duration::from_millis(100)) {
        Ok(b) => b,
        Err(e) => return ControlFlow::Break(Err(e)),
    };
    if has_event {
        let event = match crossterm::event::read() {
            Ok(event) => event,
            Err(err) => return ControlFlow::Break(Err(err)),
        };
        if let Some(key_event) = event.as_key_press_event() {
            match key_event.code {
                KeyCode::Char('1') => state.tab = Tab::Zones,
                KeyCode::Char('2') => state.tab = Tab::Policies,
                KeyCode::Char('r') if key_event.modifiers == KeyModifiers::CONTROL => {
                    state.zones.list.reset();
                    state.zones.status.clear();
                    state.policies.list.reset();
                    state.policies.info.clear();
                }
                KeyCode::Down if state.tab == Tab::Zones => {
                    state.zones.state.select_next();
                }
                KeyCode::Up if state.tab == Tab::Zones => {
                    state.zones.state.select_previous();
                }
                KeyCode::Down if state.tab == Tab::Policies => {
                    state.policies.state.select_next();
                }
                KeyCode::Up if state.tab == Tab::Policies => {
                    state.policies.state.select_previous();
                }
                KeyCode::Char('q') | KeyCode::Esc => return ControlFlow::Break(Ok(())),
                _ => {}
            }
        }
    }

    ControlFlow::Continue(())
}

fn render(state: &mut State, client: &CascadeApiClient, frame: &mut Frame) {
    let [title, tabs, main, keys_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Percentage(100),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(
        Span::styled(
            "Cascade TUI 2000: Limited Edition",
            Style::new().bold().underlined(),
        ),
        title,
    );

    let tabs_widget = Tabs::new(vec!["(1) Zones", "(2) Policies", "(3) Config"])
        .style(Style::default().white())
        .highlight_style(Style::default().bold().blue())
        .padding("", "")
        .divider(" | ")
        .select(Some(state.tab as u32 as usize));

    frame.render_widget(tabs_widget, tabs);

    match state.tab {
        Tab::Zones => zones_tab(frame, main, state, client),
        Tab::Policies => policies_tab(frame, main, state, client),
        Tab::_Config => todo!(),
    }

    let keys = [
        ("1-3", "switch tabs"),
        ("ctrl+r", "reload"),
        ("up/down", "select"),
        ("q/ESC", "quit"),
    ];

    let mut line = Line::default();

    let mut first = true;
    for (key, action) in keys {
        if !first {
            line.push_span(Span::raw(", "));
        }
        line.push_span(Span::styled(key, Style::new().blue()));
        line.push_span(Span::raw(" - "));
        line.push_span(Span::raw(action));
        first = false;
    }

    frame.render_widget(line, keys_area);
}

fn zones_tab(frame: &mut Frame, area: Rect, state: &mut State, client: &CascadeApiClient) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);

    let block = Block::bordered();
    frame.render_widget(&block, left);
    frame.render_widget(&block, right);

    let left = block.inner(left);
    let right = block.inner(right);

    let zones = {
        let client = client.clone();
        state.zones.list.get_or_fetch(move || {
            let url = "zone/";
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let response: Result<ZonesListResult, String> = runtime.block_on(client.get_json(url));
            match response {
                Ok(s) => Ok(s.zones),
                Err(e) => Err(e),
            }
        })
    };

    let Some(zones) = zones else {
        let text = Text::from("Loading...");
        draw_popup(frame, area, text);
        return;
    };

    let zones = match zones {
        Ok(zones) => zones,
        Err(e) => {
            let text = Text::from(format!("ERROR: Could not fetch zones\n{e}"));
            draw_popup(frame, area, text);
            return;
        }
    };

    let zone_names = zones.iter().map(|z| z.to_string()).collect::<Vec<_>>();
    let zone_list = List::new(zone_names)
        .style(Style::new().white())
        .highlight_style(Style::new().black().on_white())
        .highlight_symbol("> ")
        .repeat_highlight_symbol(true)
        .direction(ListDirection::TopToBottom);

    if state.zones.state.selected().is_none() && !zone_list.is_empty() {
        state.zones.state.select_first();
    }

    frame.render_stateful_widget(zone_list, left, &mut state.zones.state);

    if let Some(idx) = state.zones.state.selected()
        && let Some(name) = zones.get(idx)
    {
        let fetch = state.zones.status.entry(name.clone()).or_default();
        let name = name.clone();
        let client = client.clone();
        let res = fetch.get_or_fetch(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();

            let url = format!("zone/{name}/status");
            let response: Result<Result<ZoneStatus, ZoneStatusError>, String> =
                runtime.block_on(client.get_json(&url));

            let status = match response {
                Ok(Ok(s)) => s,
                Ok(Err(ZoneStatusError::ZoneDoesNotExist)) => {
                    return Err("zone does not exist".into());
                }
                Err(e) => return Err(e),
            };

            let policy_name = &status.policy;

            let url = format!("policy/{policy_name}");
            let response: Result<Result<PolicyInfo, PolicyInfoError>, String> =
                runtime.block_on(client.get_json(&url));

            let policy = match response {
                Ok(Ok(p)) => p,
                Ok(Err(PolicyInfoError::PolicyDoesNotExist)) => {
                    return Err("policy does not exist".into());
                }
                Err(e) => return Err(e),
            };

            Ok((status, policy))
        });
        match res {
            Some(Ok((status, policy))) => {
                let string =
                    crate::commands::zone::Zone::print_zone_status(status, policy, false).unwrap();
                let text = string.into_text().unwrap();
                let text = Paragraph::new(text);

                frame.render_widget(text, right);
            }
            Some(Err(e)) => {
                let text = Paragraph::new(e as &str);

                frame.render_widget(text, right);
            }
            None => {}
        }
    }
}

fn policies_tab(frame: &mut Frame, area: Rect, state: &mut State, client: &CascadeApiClient) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);

    let block = Block::bordered();
    frame.render_widget(&block, left);
    frame.render_widget(&block, right);

    let left = block.inner(left);
    let right = block.inner(right);

    let policies = {
        let client = client.clone();
        state.policies.list.get_or_fetch(move || {
            let url = "policy/";
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let response: Result<PolicyListResult, String> = runtime.block_on(client.get_json(url));
            match response {
                Ok(s) => Ok(s.policies),
                Err(e) => Err(e),
            }
        })
    };

    let Some(policies) = policies else {
        let text = Text::from("Loading...");
        draw_popup(frame, area, text);
        return;
    };

    let policies = match policies {
        Ok(policies) => policies,
        Err(e) => {
            let text = Text::from(format!("ERROR: Could not fetch policies\n{e}"));
            draw_popup(frame, area, text);
            return;
        }
    };

    let policy_names = policies.iter().map(|z| z.to_string()).collect::<Vec<_>>();
    let policy_list = List::new(policy_names)
        .style(Style::new().white())
        .highlight_style(Style::new().black().on_white())
        .highlight_symbol("> ")
        .repeat_highlight_symbol(true)
        .direction(ListDirection::TopToBottom);

    if state.policies.state.selected().is_none() && !policies.is_empty() {
        state.policies.state.select_first();
    }

    frame.render_stateful_widget(policy_list, left, &mut state.policies.state);

    if let Some(idx) = state.policies.state.selected()
        && let Some(name) = policies.get(idx)
    {
        let fetch = state.policies.info.entry(name.clone()).or_default();
        let name = name.clone();
        let client = client.clone();
        let res = fetch.get_or_fetch(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();

            let url = format!("policy/{name}");
            let response: Result<Result<PolicyInfo, PolicyInfoError>, String> =
                runtime.block_on(client.get_json(&url));

            let policy = match response {
                Ok(Ok(p)) => p,
                Ok(Err(PolicyInfoError::PolicyDoesNotExist)) => {
                    return Err("policy does not exist".into());
                }
                Err(e) => return Err(e),
            };

            Ok(policy)
        });
        match res {
            Some(Ok(policy)) => {
                let string = crate::commands::policy::print_policy(policy).unwrap();
                let text = string.into_text().unwrap();
                let text = Paragraph::new(text);

                frame.render_widget(text, right);
            }
            Some(Err(e)) => {
                let text = Paragraph::new(e as &str);

                frame.render_widget(text, right);
            }
            None => {}
        }
    }
}

fn draw_popup(frame: &mut Frame, area: Rect, text: Text) {
    let height = text.height();
    let width = text.width();

    let [_, area, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(height as u16 + 2),
        Constraint::Fill(1),
    ])
    .areas(area);

    let [_, area, _] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(width as u16 + 6),
        Constraint::Fill(1),
    ])
    .areas(area);

    frame.render_widget(Clear, area);
    let block = Block::bordered().padding(Padding::horizontal(2));
    frame.render_widget(&block, area);

    frame.render_widget(text, block.inner(area));
}
