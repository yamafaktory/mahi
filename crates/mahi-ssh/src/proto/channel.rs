use thiserror::Error;

use super::{
    message::Message,
    transport::{
        Transport,
        TransportError,
    },
    wire::{
        Reader,
        WireError,
        put_string,
    },
};

pub(crate) const WINDOW: u32 = 2 << 20;
pub(crate) const MAX_PACKET: u32 = 32 << 10;
const STDERR: u32 = 1;
const ADMINISTRATIVELY_PROHIBITED: u32 = 1;
const KEEPALIVE: &[u8] = b"keepalive@openssh.com";

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(crate) enum ChannelError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("the server sent message {0} where it is not allowed")]
    Unexpected(u8),
    #[error("the server named a channel that is not open")]
    UnknownChannel,
    #[error("the server sent more than the window allows")]
    WindowExceeded,
    #[error("the server's window grew beyond 2^32 - 1 bytes")]
    WindowOverflow,
    #[error("the channel can no longer send")]
    Closed,
    #[error("the server offered a largest packet of 0 bytes")]
    PacketSize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ChannelId(u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Event<'a> {
    Nothing,
    Opened(ChannelId),
    OpenFailed(ChannelId),
    WindowOpened(ChannelId),
    Succeeded(ChannelId),
    Failed(ChannelId),
    Data(ChannelId, &'a [u8]),
    Errors(ChannelId, &'a [u8]),
    Eof(ChannelId),
    ExitStatus(ChannelId, u32),
    ExitSignal(ChannelId, &'a [u8], &'a [u8]),
    Closed(ChannelId),
    KeepaliveAnswered,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Closing {
    #[default]
    Open,
    Requested,
    Sent,
}

#[derive(Debug, Default)]
struct Channel {
    remote: Option<u32>,
    remote_window: u32,
    remote_max_packet: u32,
    local_window: u32,
    consumed: u32,
    replies: u32,
    unreleased: u32,
    eof_sent: bool,
    eof_received: bool,
    closing: Closing,
}

#[derive(Debug, Default)]
pub(crate) struct Connection {
    channels: Vec<Option<Channel>>,
    keepalives: usize,
    scratch: Vec<u8>,
}

impl Connection {
    pub(crate) fn open_session(
        &mut self,
        transport: &mut Transport,
    ) -> Result<ChannelId, ChannelError> {
        let local = u32::try_from(self.channels.len()).map_err(|_| ChannelError::Closed)?;
        self.send(
            transport,
            Message::ChannelOpen {
                kind: b"session",
                sender: local,
                window: WINDOW,
                max_packet: MAX_PACKET,
                data: b"",
            },
        )?;
        self.channels.push(Some(Channel {
            local_window: WINDOW,
            ..Channel::default()
        }));
        Ok(ChannelId(local))
    }

    pub(crate) fn set_env(
        &mut self,
        transport: &mut Transport,
        id: ChannelId,
        name: &str,
        value: &str,
    ) -> Result<(), ChannelError> {
        let mut data = Vec::with_capacity(8 + name.len() + value.len());
        put_string(&mut data, name.as_bytes())?;
        put_string(&mut data, value.as_bytes())?;
        self.request(transport, id, b"env", false, &data)
    }

    pub(crate) fn exec(
        &mut self,
        transport: &mut Transport,
        id: ChannelId,
        command: &str,
    ) -> Result<(), ChannelError> {
        let mut data = Vec::with_capacity(4 + command.len());
        put_string(&mut data, command.as_bytes())?;
        self.request(transport, id, b"exec", true, &data)
    }

    fn request(
        &mut self,
        transport: &mut Transport,
        id: ChannelId,
        kind: &[u8],
        want_reply: bool,
        data: &[u8],
    ) -> Result<(), ChannelError> {
        let channel = self.live(id)?;
        let recipient = channel.remote.ok_or(ChannelError::Closed)?;
        if channel.closing != Closing::Open {
            return Err(ChannelError::Closed);
        }
        self.send(
            transport,
            Message::ChannelRequest {
                recipient,
                kind,
                want_reply,
                data,
            },
        )?;
        self.live(id)?.replies += u32::from(want_reply);
        Ok(())
    }

    pub(crate) fn send_data(
        &mut self,
        transport: &mut Transport,
        id: ChannelId,
        data: &[u8],
    ) -> Result<usize, ChannelError> {
        let channel = self.live(id)?;
        let recipient = channel.remote.ok_or(ChannelError::Closed)?;
        if channel.eof_sent || channel.closing != Closing::Open {
            return Err(ChannelError::Closed);
        }
        let chunk = channel.remote_max_packet.min(MAX_PACKET) as usize;
        let mut sent = 0;
        while transport.ready() {
            let room = self.live(id)?.remote_window as usize;
            let end = data.len().min(sent + chunk.min(room));
            if end <= sent {
                break;
            }
            let piece = data.get(sent..end).unwrap_or_default();
            self.scratch.clear();
            Message::ChannelData {
                recipient,
                data: piece,
            }
            .encode(&mut self.scratch)?;
            match transport.send(&self.scratch) {
                Ok(()) => {}
                Err(TransportError::NotReady) => break,
                Err(error) => return Err(error.into()),
            }
            let length = u32::try_from(end - sent).map_err(|_| ChannelError::WindowExceeded)?;
            self.live(id)?.remote_window -= length;
            sent = end;
        }
        Ok(sent)
    }

    pub(crate) fn send_eof(
        &mut self,
        transport: &mut Transport,
        id: ChannelId,
    ) -> Result<(), ChannelError> {
        let channel = self.live(id)?;
        let recipient = channel.remote.ok_or(ChannelError::Closed)?;
        if channel.eof_sent || channel.closing != Closing::Open {
            return Ok(());
        }
        self.send(transport, Message::ChannelEof { recipient })?;
        self.live(id)?.eof_sent = true;
        Ok(())
    }

    pub(crate) fn close(
        &mut self,
        transport: &mut Transport,
        id: ChannelId,
    ) -> Result<(), ChannelError> {
        let channel = self.live(id)?;
        let Some(recipient) = channel.remote else {
            channel.closing = Closing::Requested;
            return Ok(());
        };
        if channel.closing == Closing::Sent {
            return Ok(());
        }
        self.send(transport, Message::ChannelClose { recipient })?;
        self.live(id)?.closing = Closing::Sent;
        Ok(())
    }

    pub(crate) fn consumed(
        &mut self,
        transport: &mut Transport,
        id: ChannelId,
        count: usize,
    ) -> Result<(), ChannelError> {
        let Ok(channel) = self.live(id) else {
            return Ok(());
        };
        let count = u32::try_from(count)
            .unwrap_or(u32::MAX)
            .min(channel.unreleased);
        channel.unreleased -= count;
        channel.consumed += count;
        if channel.consumed < WINDOW / 2 || channel.closing == Closing::Sent {
            return Ok(());
        }
        let Some(recipient) = channel.remote else {
            return Ok(());
        };
        let bytes = channel.consumed;
        self.send(transport, Message::ChannelWindowAdjust { recipient, bytes })?;
        let channel = self.live(id)?;
        channel.consumed = 0;
        channel.local_window += bytes;
        Ok(())
    }

    pub(crate) fn keepalive(&mut self, transport: &mut Transport) -> Result<usize, ChannelError> {
        self.send(
            transport,
            Message::GlobalRequest {
                name: KEEPALIVE,
                want_reply: true,
                data: b"",
            },
        )?;
        self.keepalives += 1;
        Ok(self.keepalives)
    }

    pub(crate) fn unanswered_keepalives(&self) -> usize {
        self.keepalives
    }

    pub(crate) fn handle<'a>(
        &mut self,
        transport: &mut Transport,
        payload: &'a [u8],
    ) -> Result<Event<'a>, ChannelError> {
        let message = Message::decode(payload)?;
        if let Some(event) = self.handle_global(transport, &message)? {
            return Ok(event);
        }
        match message {
            Message::ChannelOpenConfirmation {
                recipient,
                sender,
                window,
                max_packet,
                ..
            } => self.on_confirmation(transport, recipient, sender, window, max_packet),
            Message::ChannelOpenFailure { recipient, .. } => {
                let id = ChannelId(recipient);
                if self.live(id)?.remote.is_some() {
                    return Err(ChannelError::Unexpected(
                        payload.first().copied().unwrap_or_default(),
                    ));
                }
                self.remove(id);
                Ok(Event::OpenFailed(id))
            }
            Message::ChannelWindowAdjust { recipient, bytes } => {
                let id = ChannelId(recipient);
                let channel = self.confirmed(id)?;
                channel.remote_window = channel
                    .remote_window
                    .checked_add(bytes)
                    .ok_or(ChannelError::WindowOverflow)?;
                Ok(Event::WindowOpened(id))
            }
            Message::ChannelData { recipient, data } => {
                let id = ChannelId(recipient);
                self.receive(id, data.len())?;
                Ok(Event::Data(id, data))
            }
            Message::ChannelExtendedData {
                recipient,
                code,
                data,
            } => {
                let id = ChannelId(recipient);
                self.receive(id, data.len())?;
                if code == STDERR {
                    Ok(Event::Errors(id, data))
                } else {
                    self.consumed(transport, id, data.len())?;
                    Ok(Event::Nothing)
                }
            }
            Message::ChannelEof { recipient } => {
                let id = ChannelId(recipient);
                let channel = self.confirmed(id)?;
                if channel.eof_received {
                    return Err(ChannelError::Unexpected(
                        payload.first().copied().unwrap_or_default(),
                    ));
                }
                channel.eof_received = true;
                Ok(Event::Eof(id))
            }
            Message::ChannelClose { recipient } => {
                let id = ChannelId(recipient);
                self.confirmed(id)?;
                let reply = self.close(transport, id);
                self.remove(id);
                reply?;
                Ok(Event::Closed(id))
            }
            Message::ChannelRequest {
                recipient,
                kind,
                want_reply,
                data,
            } => self.on_request(transport, ChannelId(recipient), kind, want_reply, data),
            Message::ChannelSuccess { recipient } | Message::ChannelFailure { recipient } => {
                let id = ChannelId(recipient);
                let channel = self.confirmed(id)?;
                channel.replies =
                    channel
                        .replies
                        .checked_sub(1)
                        .ok_or(ChannelError::Unexpected(
                            payload.first().copied().unwrap_or_default(),
                        ))?;
                Ok(if matches!(message, Message::ChannelSuccess { .. }) {
                    Event::Succeeded(id)
                } else {
                    Event::Failed(id)
                })
            }
            _ => Err(ChannelError::Unexpected(
                payload.first().copied().unwrap_or_default(),
            )),
        }
    }

    fn handle_global(
        &mut self,
        transport: &mut Transport,
        message: &Message<'_>,
    ) -> Result<Option<Event<'static>>, ChannelError> {
        match message {
            &Message::GlobalRequest { want_reply, .. } => {
                if want_reply {
                    self.send(transport, Message::RequestFailure)?;
                }
                Ok(Some(Event::Nothing))
            }
            Message::RequestSuccess { .. } | Message::RequestFailure => {
                self.keepalives = self
                    .keepalives
                    .checked_sub(1)
                    .ok_or(ChannelError::Unexpected(super::message::REQUEST_FAILURE))?;
                Ok(Some(Event::KeepaliveAnswered))
            }
            &Message::ChannelOpen { sender, .. } => {
                self.send(
                    transport,
                    Message::ChannelOpenFailure {
                        recipient: sender,
                        reason: ADMINISTRATIVELY_PROHIBITED,
                        description: b"mahi accepts no channels",
                    },
                )?;
                Ok(Some(Event::Nothing))
            }
            _ => Ok(None),
        }
    }

    fn on_request<'a>(
        &mut self,
        transport: &mut Transport,
        id: ChannelId,
        kind: &[u8],
        want_reply: bool,
        data: &'a [u8],
    ) -> Result<Event<'a>, ChannelError> {
        let channel = self.confirmed(id)?;
        let remote = channel.remote.ok_or(ChannelError::UnknownChannel)?;
        let closing = channel.closing == Closing::Sent;
        match (kind, want_reply) {
            (b"exit-status", false) => {
                let mut reader = Reader::new(data);
                let status = reader.u32()?;
                reader.finish()?;
                Ok(Event::ExitStatus(id, status))
            }
            (b"exit-signal", false) => {
                let mut reader = Reader::new(data);
                let signal = reader.string()?;
                reader.bool()?;
                let message = reader.string()?;
                reader.string()?;
                reader.finish()?;
                Ok(Event::ExitSignal(id, signal, message))
            }
            (_, true) if !closing => {
                self.send(transport, Message::ChannelFailure { recipient: remote })?;
                Ok(Event::Nothing)
            }
            _ => Ok(Event::Nothing),
        }
    }

    fn on_confirmation(
        &mut self,
        transport: &mut Transport,
        recipient: u32,
        sender: u32,
        window: u32,
        max_packet: u32,
    ) -> Result<Event<'static>, ChannelError> {
        let id = ChannelId(recipient);
        let channel = self.live(id)?;
        if channel.remote.is_some() {
            return Err(ChannelError::Unexpected(
                super::message::CHANNEL_OPEN_CONFIRMATION,
            ));
        }
        if max_packet == 0 {
            return Err(ChannelError::PacketSize);
        }
        channel.remote = Some(sender);
        channel.remote_window = window;
        channel.remote_max_packet = max_packet;
        if channel.closing == Closing::Requested {
            self.close(transport, id)?;
        }
        Ok(Event::Opened(id))
    }

    fn receive(&mut self, id: ChannelId, length: usize) -> Result<(), ChannelError> {
        let channel = self.confirmed(id)?;
        let length = u32::try_from(length).map_err(|_| ChannelError::WindowExceeded)?;
        if channel.eof_received {
            return Err(ChannelError::Unexpected(super::message::CHANNEL_DATA));
        }
        if length > MAX_PACKET || length > channel.local_window {
            return Err(ChannelError::WindowExceeded);
        }
        channel.local_window -= length;
        channel.unreleased += length;
        Ok(())
    }

    fn live(&mut self, id: ChannelId) -> Result<&mut Channel, ChannelError> {
        self.channels
            .get_mut(id.0 as usize)
            .and_then(Option::as_mut)
            .ok_or(ChannelError::UnknownChannel)
    }

    fn confirmed(&mut self, id: ChannelId) -> Result<&mut Channel, ChannelError> {
        let channel = self.live(id)?;
        if channel.remote.is_none() {
            return Err(ChannelError::UnknownChannel);
        }
        Ok(channel)
    }

    fn remove(&mut self, id: ChannelId) {
        if let Some(slot) = self.channels.get_mut(id.0 as usize) {
            *slot = None;
        }
    }

    fn send(
        &mut self,
        transport: &mut Transport,
        message: Message<'_>,
    ) -> Result<(), ChannelError> {
        self.scratch.clear();
        message.encode(&mut self.scratch)?;
        transport.send(&self.scratch)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        kex::HostKeyAlgorithm,
        message,
        test_server::{
            TestServer,
            connected,
            pump,
        },
        transport::Poll,
    };

    struct Pair {
        client: Transport,
        server: TestServer,
        connection: Connection,
    }

    impl Pair {
        fn new() -> Self {
            let (mut client, server) = connected(HostKeyAlgorithm::Ed25519);
            client.set_authenticated();
            Self {
                client,
                server,
                connection: Connection::default(),
            }
        }

        fn events(&mut self) -> Result<Vec<String>, ChannelError> {
            let mut events = Vec::new();
            loop {
                match pump(&mut self.client, &mut self.server)? {
                    Poll::Message => {
                        let payload = self.client.message().to_vec();
                        let event = self.connection.handle(&mut self.client, &payload)?;
                        events.push(format!("{event:?}"));
                    }
                    Poll::Pending => return Ok(events),
                    Poll::HostKey => unreachable!(),
                }
            }
        }

        fn sent(&mut self) -> Vec<Vec<u8>> {
            let _ = pump(&mut self.client, &mut self.server);
            std::mem::take(&mut self.server.received)
        }

        fn open(&mut self, window: u32, max_packet: u32) -> ChannelId {
            let id = self.connection.open_session(&mut self.client).unwrap();
            let sent = self.sent();
            let Message::ChannelOpen {
                kind: b"session",
                sender,
                window: WINDOW,
                max_packet: MAX_PACKET,
                ..
            } = Message::decode(&sent[0]).unwrap()
            else {
                panic!("not a session open: {sent:?}");
            };
            self.server.send_message(Message::ChannelOpenConfirmation {
                recipient: sender,
                sender: 70 + sender,
                window,
                max_packet,
                data: b"",
            });
            assert_eq!(self.events().unwrap(), [format!("Opened({id:?})")]);
            id
        }
    }

    fn data(id: ChannelId, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        Message::ChannelData {
            recipient: id.0,
            data: bytes,
        }
        .encode(&mut out)
        .unwrap();
        out
    }

    #[test]
    fn a_command_runs_from_open_to_close() {
        let mut pair = Pair::new();
        let id = pair.open(1 << 20, 32 << 10);
        pair.connection
            .set_env(&mut pair.client, id, "GIT_PROTOCOL", "version=2")
            .unwrap();
        pair.connection
            .exec(&mut pair.client, id, "git-upload-pack 'repo'")
            .unwrap();
        let sent = pair.sent();
        let Message::ChannelRequest {
            recipient: 70,
            kind: b"env",
            want_reply: false,
            ..
        } = Message::decode(&sent[0]).unwrap()
        else {
            panic!("{sent:?}");
        };
        let Message::ChannelRequest {
            recipient: 70,
            kind: b"exec",
            want_reply: true,
            data: command,
        } = Message::decode(&sent[1]).unwrap()
        else {
            panic!("{sent:?}");
        };
        assert_eq!(&command[4..], b"git-upload-pack 'repo'");
        pair.server
            .send_message(Message::ChannelSuccess { recipient: id.0 });
        pair.server.send(&data(id, b"output"));
        pair.server.send_message(Message::ChannelExtendedData {
            recipient: id.0,
            code: 1,
            data: b"warning",
        });
        let mut status = Vec::new();
        crate::proto::wire::put_u32(&mut status, 3);
        pair.server.send_message(Message::ChannelRequest {
            recipient: id.0,
            kind: b"exit-status",
            want_reply: false,
            data: &status,
        });
        pair.server
            .send_message(Message::ChannelEof { recipient: id.0 });
        pair.server
            .send_message(Message::ChannelClose { recipient: id.0 });
        assert_eq!(
            pair.events().unwrap(),
            [
                format!("Succeeded({id:?})"),
                format!("Data({id:?}, {:?})", b"output"),
                format!("Errors({id:?}, {:?})", b"warning"),
                format!("ExitStatus({id:?}, 3)"),
                format!("Eof({id:?})"),
                format!("Closed({id:?})"),
            ]
        );
        assert_eq!(pair.sent(), [vec![message::CHANNEL_CLOSE, 0, 0, 0, 70]]);
        pair.server
            .send_message(Message::ChannelClose { recipient: id.0 });
        assert_eq!(pair.events(), Err(ChannelError::UnknownChannel));
    }

    #[test]
    fn sending_follows_the_servers_window_and_packet_size() {
        let mut pair = Pair::new();
        let id = pair.open(100, 30);
        assert_eq!(
            pair.connection.send_data(&mut pair.client, id, &[1; 250]),
            Ok(100)
        );
        let lengths: Vec<usize> = pair
            .sent()
            .iter()
            .map(|payload| match Message::decode(payload).unwrap() {
                Message::ChannelData {
                    recipient: 70,
                    data,
                } => data.len(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(lengths, [30, 30, 30, 10]);
        assert_eq!(
            pair.connection.send_data(&mut pair.client, id, &[1; 10]),
            Ok(0)
        );
        pair.server.send_message(Message::ChannelWindowAdjust {
            recipient: id.0,
            bytes: 50,
        });
        assert_eq!(pair.events().unwrap(), [format!("WindowOpened({id:?})")]);
        assert_eq!(
            pair.connection.send_data(&mut pair.client, id, &[1; 80]),
            Ok(50)
        );
        pair.connection.send_eof(&mut pair.client, id).unwrap();
        assert_eq!(
            pair.connection.send_data(&mut pair.client, id, &[1]),
            Err(ChannelError::Closed)
        );
    }

    #[test]
    fn a_server_packet_size_of_zero_is_refused() {
        let mut pair = Pair::new();
        let id = pair.connection.open_session(&mut pair.client).unwrap();
        pair.server.send_message(Message::ChannelOpenConfirmation {
            recipient: id.0,
            sender: 70,
            window: 100,
            max_packet: 0,
            data: b"",
        });
        assert_eq!(pair.events(), Err(ChannelError::PacketSize));
    }

    #[test]
    fn eof_is_sent_once_and_never_after_close() {
        let mut pair = Pair::new();
        let id = pair.open(100, 30);
        pair.connection.send_eof(&mut pair.client, id).unwrap();
        pair.connection.send_eof(&mut pair.client, id).unwrap();
        assert_eq!(pair.sent(), [vec![message::CHANNEL_EOF, 0, 0, 0, 70]]);
        let other = pair.open(100, 30);
        pair.connection.close(&mut pair.client, other).unwrap();
        pair.connection.send_eof(&mut pair.client, other).unwrap();
        pair.connection.close(&mut pair.client, other).unwrap();
        assert_eq!(pair.sent(), [vec![message::CHANNEL_CLOSE, 0, 0, 0, 71]]);
    }

    #[test]
    fn a_window_grown_past_its_limit_ends_the_connection() {
        let mut pair = Pair::new();
        let id = pair.open(u32::MAX - 5, 30);
        pair.server.send_message(Message::ChannelWindowAdjust {
            recipient: id.0,
            bytes: 6,
        });
        assert_eq!(pair.events(), Err(ChannelError::WindowOverflow));
    }

    #[test]
    fn the_window_is_topped_up_once_half_of_it_is_read() {
        let chunk = vec![7; MAX_PACKET as usize];
        let mut pair = Pair::new();
        let id = pair.open(1 << 20, 32 << 10);
        for _ in 0..(WINDOW / MAX_PACKET) {
            pair.server.send(&data(id, &chunk));
        }
        assert_eq!(pair.events().unwrap().len(), (WINDOW / MAX_PACKET) as usize);
        pair.server.send(&data(id, b"x"));
        assert_eq!(pair.events(), Err(ChannelError::WindowExceeded));

        let mut pair = Pair::new();
        let id = pair.open(1 << 20, 32 << 10);
        for _ in 0..(WINDOW / MAX_PACKET) {
            pair.server.send(&data(id, &chunk));
        }
        pair.events().unwrap();
        pair.connection
            .consumed(&mut pair.client, id, (WINDOW / 2 - 1) as usize)
            .unwrap();
        assert!(pair.sent().is_empty());
        pair.connection.consumed(&mut pair.client, id, 1).unwrap();
        assert_eq!(
            Message::decode(&pair.sent()[0]),
            Ok(Message::ChannelWindowAdjust {
                recipient: 70,
                bytes: WINDOW / 2
            })
        );
        for _ in 0..(WINDOW / 2 / MAX_PACKET) {
            pair.server.send(&data(id, &chunk));
        }
        assert_eq!(
            pair.events().unwrap().len(),
            (WINDOW / 2 / MAX_PACKET) as usize
        );
        pair.server.send(&data(id, b"x"));
        assert_eq!(pair.events(), Err(ChannelError::WindowExceeded));
    }

    #[test]
    fn only_received_bytes_can_be_released() {
        let mut pair = Pair::new();
        let id = pair.open(1 << 20, 32 << 10);
        pair.connection
            .consumed(&mut pair.client, id, WINDOW as usize)
            .unwrap();
        assert!(pair.sent().is_empty());
        let chunk = vec![7; MAX_PACKET as usize];
        for _ in 0..(WINDOW / 2 / MAX_PACKET) {
            pair.server.send(&data(id, &chunk));
        }
        pair.events().unwrap();
        pair.connection
            .consumed(&mut pair.client, id, usize::MAX)
            .unwrap();
        assert_eq!(
            Message::decode(&pair.sent()[0]),
            Ok(Message::ChannelWindowAdjust {
                recipient: 70,
                bytes: WINDOW / 2
            })
        );
        pair.connection
            .consumed(&mut pair.client, id, usize::MAX)
            .unwrap();
        assert!(pair.sent().is_empty());
        assert_eq!(pair.connection.live(id).unwrap().unreleased, 0);
    }

    #[test]
    fn a_closed_channel_takes_no_more_requests_or_data() {
        let mut pair = Pair::new();
        let id = pair.open(100, 30);
        pair.connection.close(&mut pair.client, id).unwrap();
        assert_eq!(
            pair.connection.exec(&mut pair.client, id, "x"),
            Err(ChannelError::Closed)
        );
        assert_eq!(
            pair.connection.send_data(&mut pair.client, id, b"x"),
            Err(ChannelError::Closed)
        );
    }

    #[test]
    fn a_rekey_during_a_send_stops_it_and_keeps_the_window_right() {
        let mut pair = Pair::new();
        let id = pair.open(1 << 20, 32 << 10);
        pair.client.set_rekey_after(100_000, u64::MAX);
        let sent = pair
            .connection
            .send_data(&mut pair.client, id, &vec![1; 300_000])
            .unwrap();
        assert!(sent > 0 && sent < 300_000, "{sent}");
        assert!(!pair.client.ready());
        pair.events().unwrap();
        assert!(pair.client.ready());
        let rest = pair
            .connection
            .send_data(&mut pair.client, id, &vec![1; 300_000 - sent])
            .unwrap();
        let delivered: usize = pair
            .sent()
            .iter()
            .filter_map(|payload| match Message::decode(payload) {
                Ok(Message::ChannelData { data, .. }) => Some(data.len()),
                _ => None,
            })
            .sum();
        assert_eq!(delivered, sent + rest);
        assert_eq!(
            pair.connection.live(id).unwrap().remote_window as usize,
            (1 << 20) - sent - rest
        );
    }

    #[test]
    fn closing_before_the_confirmation_closes_once_confirmed() {
        let mut pair = Pair::new();
        let id = pair.connection.open_session(&mut pair.client).unwrap();
        pair.connection.close(&mut pair.client, id).unwrap();
        assert_eq!(pair.sent().len(), 1);
        pair.server.send_message(Message::ChannelOpenConfirmation {
            recipient: id.0,
            sender: 70,
            window: 100,
            max_packet: 30,
            data: b"",
        });
        assert_eq!(pair.events().unwrap(), [format!("Opened({id:?})")]);
        assert_eq!(pair.sent(), [vec![message::CHANNEL_CLOSE, 0, 0, 0, 70]]);
        assert_eq!(
            pair.connection.exec(&mut pair.client, id, "x"),
            Err(ChannelError::Closed)
        );
    }

    #[test]
    fn nothing_answers_a_request_after_our_close() {
        let mut pair = Pair::new();
        let id = pair.open(100, 30);
        pair.connection.close(&mut pair.client, id).unwrap();
        pair.sent();
        pair.server.send_message(Message::ChannelRequest {
            recipient: id.0,
            kind: b"keepalive@openssh.com",
            want_reply: true,
            data: b"",
        });
        assert_eq!(pair.events().unwrap(), ["Nothing"]);
        assert!(pair.sent().is_empty());
    }

    #[test]
    fn channel_ids_are_never_reused_on_a_connection() {
        let mut pair = Pair::new();
        let first = pair.open(100, 30);
        pair.server
            .send_message(Message::ChannelClose { recipient: first.0 });
        pair.events().unwrap();
        let second = pair.connection.open_session(&mut pair.client).unwrap();
        assert_ne!(second, first);
        assert_eq!(
            pair.connection.send_data(&mut pair.client, first, b"stale"),
            Err(ChannelError::UnknownChannel)
        );
    }

    #[test]
    fn a_failed_send_leaves_the_channel_state_unchanged() {
        let mut pair = Pair::new();
        let id = pair.open(100, 30);
        pair.client.start_rekey().unwrap();
        let big = vec![0; 200 << 10];
        pair.client.send(&big).unwrap();
        pair.client.send(&big).unwrap_err();
        assert!(pair.connection.send_eof(&mut pair.client, id).is_err());
        assert!(!pair.connection.live(id).unwrap().eof_sent);
        assert!(pair.connection.exec(&mut pair.client, id, "x").is_err());
        assert_eq!(pair.connection.live(id).unwrap().replies, 0);
        assert!(pair.connection.close(&mut pair.client, id).is_err());
        assert_eq!(pair.connection.live(id).unwrap().closing, Closing::Open);
    }

    #[test]
    fn a_data_packet_larger_than_offered_is_refused() {
        let mut pair = Pair::new();
        let id = pair.open(1 << 20, 32 << 10);
        pair.server
            .send(&data(id, &vec![0; MAX_PACKET as usize + 1]));
        assert_eq!(pair.events(), Err(ChannelError::WindowExceeded));
    }

    #[test]
    fn data_after_eof_or_for_a_channel_not_open_is_refused() {
        let mut pair = Pair::new();
        let id = pair.open(100, 30);
        pair.server
            .send_message(Message::ChannelEof { recipient: id.0 });
        pair.server.send(&data(id, b"late"));
        assert_eq!(
            pair.events(),
            Err(ChannelError::Unexpected(message::CHANNEL_DATA))
        );
        let mut pair = Pair::new();
        pair.server.send(&data(ChannelId(0), b"nobody"));
        assert_eq!(pair.events(), Err(ChannelError::UnknownChannel));
        let mut pair = Pair::new();
        let id = pair.connection.open_session(&mut pair.client).unwrap();
        pair.server.send(&data(id, b"too early"));
        assert_eq!(pair.events(), Err(ChannelError::UnknownChannel));
    }

    #[test]
    fn a_second_confirmation_or_eof_is_refused() {
        let mut pair = Pair::new();
        let id = pair.open(100, 30);
        pair.server.send_message(Message::ChannelOpenConfirmation {
            recipient: id.0,
            sender: 1,
            window: 1,
            max_packet: 1,
            data: b"",
        });
        assert_eq!(
            pair.events(),
            Err(ChannelError::Unexpected(message::CHANNEL_OPEN_CONFIRMATION))
        );
        let mut pair = Pair::new();
        let id = pair.open(100, 30);
        pair.server
            .send_message(Message::ChannelEof { recipient: id.0 });
        pair.server
            .send_message(Message::ChannelEof { recipient: id.0 });
        assert_eq!(
            pair.events(),
            Err(ChannelError::Unexpected(message::CHANNEL_EOF))
        );
    }

    #[test]
    fn a_refused_open_removes_the_channel() {
        let mut pair = Pair::new();
        let id = pair.connection.open_session(&mut pair.client).unwrap();
        pair.server.send_message(Message::ChannelOpenFailure {
            recipient: id.0,
            reason: 4,
            description: b"no",
        });
        assert_eq!(pair.events().unwrap(), [format!("OpenFailed({id:?})")]);
        assert_eq!(
            pair.connection.exec(&mut pair.client, id, "x"),
            Err(ChannelError::UnknownChannel)
        );
    }

    #[test]
    fn channels_and_requests_from_the_server_are_refused() {
        let mut pair = Pair::new();
        let id = pair.open(100, 30);
        pair.server.send_message(Message::ChannelOpen {
            kind: b"x11",
            sender: 9,
            window: 100,
            max_packet: 100,
            data: b"",
        });
        pair.server.send_message(Message::GlobalRequest {
            name: b"tcpip-forward",
            want_reply: true,
            data: b"",
        });
        pair.server.send_message(Message::GlobalRequest {
            name: b"hostkeys-00@openssh.com",
            want_reply: false,
            data: b"",
        });
        pair.server.send_message(Message::ChannelRequest {
            recipient: id.0,
            kind: b"keepalive@openssh.com",
            want_reply: true,
            data: b"",
        });
        assert_eq!(
            pair.events().unwrap(),
            ["Nothing", "Nothing", "Nothing", "Nothing"]
        );
        let replies = pair.sent();
        assert_eq!(
            Message::decode(&replies[0]),
            Ok(Message::ChannelOpenFailure {
                recipient: 9,
                reason: ADMINISTRATIVELY_PROHIBITED,
                description: b"mahi accepts no channels"
            })
        );
        assert_eq!(Message::decode(&replies[1]), Ok(Message::RequestFailure));
        assert_eq!(
            Message::decode(&replies[2]),
            Ok(Message::ChannelFailure { recipient: 70 })
        );
        assert_eq!(replies.len(), 3);
    }

    #[test]
    fn keepalives_are_counted_until_answered() {
        let mut pair = Pair::new();
        assert_eq!(pair.connection.keepalive(&mut pair.client), Ok(1));
        assert_eq!(pair.connection.keepalive(&mut pair.client), Ok(2));
        assert_eq!(pair.connection.unanswered_keepalives(), 2);
        assert_eq!(
            Message::decode(&pair.sent()[0]),
            Ok(Message::GlobalRequest {
                name: KEEPALIVE,
                want_reply: true,
                data: b""
            })
        );
        pair.server.send_message(Message::RequestFailure);
        pair.server
            .send_message(Message::RequestSuccess { data: b"" });
        assert_eq!(
            pair.events().unwrap(),
            ["KeepaliveAnswered", "KeepaliveAnswered"]
        );
        assert_eq!(pair.connection.unanswered_keepalives(), 0);
        pair.server.send_message(Message::RequestFailure);
        assert_eq!(
            pair.events(),
            Err(ChannelError::Unexpected(message::REQUEST_FAILURE))
        );
    }

    #[test]
    fn exit_signals_are_reported_and_replies_need_a_request() {
        let mut pair = Pair::new();
        let id = pair.open(100, 30);
        let mut signal = Vec::new();
        put_string(&mut signal, b"KILL").unwrap();
        signal.push(0);
        put_string(&mut signal, b"out of memory").unwrap();
        put_string(&mut signal, b"").unwrap();
        pair.server.send_message(Message::ChannelRequest {
            recipient: id.0,
            kind: b"exit-signal",
            want_reply: false,
            data: &signal,
        });
        assert_eq!(
            pair.events().unwrap(),
            [format!(
                "ExitSignal({id:?}, {:?}, {:?})",
                b"KILL", b"out of memory"
            )]
        );
        pair.server
            .send_message(Message::ChannelSuccess { recipient: id.0 });
        assert_eq!(
            pair.events(),
            Err(ChannelError::Unexpected(message::CHANNEL_SUCCESS))
        );
    }

    #[test]
    fn other_extended_data_is_read_and_released() {
        let mut pair = Pair::new();
        let id = pair.open(100, 30);
        let chunk = vec![0; MAX_PACKET as usize];
        for _ in 0..(WINDOW / 2 / MAX_PACKET) {
            pair.server.send_message(Message::ChannelExtendedData {
                recipient: id.0,
                code: 2,
                data: &chunk,
            });
        }
        let events = pair.events().unwrap();
        assert!(events.iter().all(|event| event == "Nothing"));
        assert_eq!(
            pair.sent()
                .iter()
                .map(|payload| Message::decode(payload).unwrap())
                .collect::<Vec<_>>(),
            [Message::ChannelWindowAdjust {
                recipient: 70,
                bytes: WINDOW / 2
            }]
        );
    }

    #[test]
    fn no_data_is_sent_during_a_rekey() {
        let mut pair = Pair::new();
        let id = pair.open(100, 30);
        pair.client.start_rekey().unwrap();
        assert_eq!(
            pair.connection.send_data(&mut pair.client, id, b"wait"),
            Ok(0)
        );
        pair.events().unwrap();
        assert_eq!(
            pair.connection.send_data(&mut pair.client, id, b"now"),
            Ok(3)
        );
    }
}
