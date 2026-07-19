#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectAction {
    Tunnel,
    Mitm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestAction {
    Allow,
    Deny,
}

pub fn should_intercept_connect(allowed: bool, pinned: bool) -> bool {
    !(allowed && pinned)
}

pub fn connect_action(allowed: bool, pinned: bool) -> ConnectAction {
    if should_intercept_connect(allowed, pinned) {
        ConnectAction::Mitm
    } else {
        ConnectAction::Tunnel
    }
}

pub fn request_action(allowed: bool) -> RequestAction {
    if allowed {
        RequestAction::Allow
    } else {
        RequestAction::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_and_pinned_tunnels_without_interception() {
        assert!(!should_intercept_connect(true, true));
        assert_eq!(connect_action(true, true), ConnectAction::Tunnel);
    }

    #[test]
    fn allowed_but_unpinned_is_intercepted() {
        assert!(should_intercept_connect(true, false));
        assert_eq!(connect_action(true, false), ConnectAction::Mitm);
    }

    #[test]
    fn denied_is_intercepted_regardless_of_pinning() {
        assert!(should_intercept_connect(false, true));
        assert!(should_intercept_connect(false, false));
        assert_eq!(connect_action(false, true), ConnectAction::Mitm);
        assert_eq!(connect_action(false, false), ConnectAction::Mitm);
    }

    #[test]
    fn request_action_follows_allow_flag() {
        assert_eq!(request_action(true), RequestAction::Allow);
        assert_eq!(request_action(false), RequestAction::Deny);
    }
}
