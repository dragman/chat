extern crate http_muncher;
extern crate mio;
extern crate rustc_serialize;
extern crate sha1;

mod frame;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::cell::RefCell;
use std::rc::Rc;
use rustc_serialize::base64::{ToBase64, STANDARD};
use std::net::SocketAddr;

fn gen_key(key: &String) -> String {
    let mut m = sha1::Sha1::new();
    let mut buf = [0u8; 20];

    m.update(key.as_bytes());
    m.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11".as_bytes());

    m.output(&mut buf);

    return buf.to_base64(STANDARD);
}

#[derive(PartialEq)]
struct HttpParser {
    current_key: Option<String>,
    headers: Rc<RefCell<HashMap<String, String>>>,
}

#[derive(PartialEq)]
enum ClientState {
    AwaitingHandshake(RefCell<HttpParser>),
    HandshakeResponse,
    Connected,
}

impl http_muncher::ParserHandler for HttpParser {
    fn on_header_field(&mut self, _parser: &mut http_muncher::Parser, s: &[u8]) -> bool {
        self.current_key = Some(std::str::from_utf8(s).unwrap().to_string());
        println!(
            "received header field: {}",
            self.current_key.clone().unwrap_or_default()
        );
        true
    }

    fn on_header_value(&mut self, _parser: &mut http_muncher::Parser, s: &[u8]) -> bool {
        self.headers.borrow_mut().insert(
            self.current_key.clone().unwrap(),
            std::str::from_utf8(s).unwrap().to_string(),
        );
        true
    }

    fn on_headers_complete(&mut self, _parser: &mut http_muncher::Parser) -> bool {
        false
    }
}

const SERVER_TOKEN: mio::Token = mio::Token(0);

struct WebSocketClient {
    socket: mio::tcp::TcpStream,
    headers: Rc<RefCell<HashMap<String, String>>>,
    interest: mio::Ready,
    state: ClientState,
    outgoing: Vec<frame::WebSocketFrame>,
}

impl WebSocketClient {
    fn read_handshake(&mut self) {
        loop {
            let mut buf = [0; 2048];
            match self.socket.read(&mut buf) {
                Err(e) => {
                    println!("Error reading socket: {:?}", e);
                    return;
                }
                Ok(0) => {
                    println!("Socket disconnected");
                    break;
                }
                Ok(len) => {
                    let is_upgrade =
                        if let ClientState::AwaitingHandshake(ref mut parser_state) = self.state {
                            let mut parser = parser_state.borrow_mut();
                            let mut parser_request = http_muncher::Parser::request();
                            parser_request.parse(&mut *parser, &buf[0..len]);
                            parser_request.is_upgrade()
                        } else {
                            false
                        };

                    if is_upgrade {
                        self.state = ClientState::HandshakeResponse;

                        self.interest.remove(mio::Ready::readable());
                        self.interest.insert(mio::Ready::writable());

                        break;
                    }
                }
            }
        }
    }

    fn read_frame(&mut self) {
        let frame = frame::WebSocketFrame::read(&mut self.socket);
        match frame {
            Ok(frame) => match frame.get_opcode() {
                frame::OpCode::TextFrame => {
                    println!("received = {:?}", frame);
                    let reply_frame =
                        frame::WebSocketFrame::from("Welcome to the convoest of the bongos!");
                    println!("replying = {:?}", reply_frame);
                    self.outgoing.push(reply_frame);
                }
                frame::OpCode::Ping => {
                    println!("ping/pong");
                    self.outgoing.push(frame::WebSocketFrame::pong(&frame));
                }
                frame::OpCode::ConnectionClose => {
                    self.outgoing.push(frame::WebSocketFrame::from_close(&frame));
                }
                _ => {}
            },
            Err(e) => println!("error while reading frame: {}", e),
        }

        if self.outgoing.len() > 0 {
            self.interest.remove(mio::Ready::readable());
            self.interest.insert(mio::Ready::writable());
        }
    }

    fn read(&mut self) {
        match self.state {
            ClientState::AwaitingHandshake(_) => self.read_handshake(),
            ClientState::Connected => self.read_frame(),
            _ => {}
        }
    }

    fn write(&mut self) {
        match self.state {
            ClientState::HandshakeResponse => {
                self.write_handshake();
            }
            ClientState::Connected => {
                println!("sending {} frames", self.outgoing.len());

                let mut close_connection = false;

                for frame in self.outgoing.iter() {
                    if let Err(e) = frame.write(&mut self.socket) {
                        println!("error on write: {}", e);
                    }

                    if frame.get_opcode() == frame::OpCode::ConnectionClose {
                        close_connection = true;
                    }
                }

                self.outgoing.clear();
                self.interest.remove(mio::Ready::writable());

                if close_connection {
                    self.interest.insert(mio::Ready::hup());
                } else {
                    self.interest.insert(mio::Ready::readable());
                }
                
            }
            _ => {
                println!("unknown client state");
            }
        }
    }

    fn write_handshake(&mut self) {
        let headers = self.headers.borrow();
        let response_key = gen_key(&headers.get("Sec-WebSocket-Key").unwrap());
        let response = std::fmt::format(format_args!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\
             Upgrade: websocket\r\n\r\n",
            response_key
        ));

        println!("Responding with: {}", response);
        self.socket.write(response.as_bytes()).unwrap();

        self.state = ClientState::Connected;

        self.interest.remove(mio::Ready::writable());
        self.interest.insert(mio::Ready::readable());
    }

    fn new(socket: mio::tcp::TcpStream) -> WebSocketClient {
        let headers = Rc::new(RefCell::new(HashMap::new()));

        WebSocketClient {
            socket: socket,
            headers: headers.clone(),
            interest: mio::Ready::readable(),
            state: ClientState::AwaitingHandshake(RefCell::new(HttpParser {
                current_key: None,
                headers: headers.clone(),
            })),
            outgoing: Vec::new(),
        }
    }
}

impl mio::Evented for WebSocketClient {
    fn register(
        &self,
        poll: &mio::Poll,
        token: mio::Token,
        interest: mio::Ready,
        opts: mio::PollOpt,
    ) -> std::io::Result<()> {
        self.socket.register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &mio::Poll,
        token: mio::Token,
        interest: mio::Ready,
        opts: mio::PollOpt,
    ) -> std::io::Result<()> {
        self.socket.reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &mio::Poll) -> std::io::Result<()> {
        self.socket.deregister(poll)
    }
}

struct WebSocketServer {
    socket: mio::net::TcpListener,
    clients: HashMap<mio::Token, WebSocketClient>,
    token_counter: usize,
    poll: mio::Poll,
    events: mio::Events,
}

impl WebSocketServer {
    fn run(&mut self) {
        self.poll
            .register(
                &self.socket,
                SERVER_TOKEN,
                mio::Ready::readable(),
                mio::PollOpt::edge(),
            )
            .unwrap();

        loop {
            self.poll.poll(&mut self.events, None).unwrap();

            for event in &self.events {
                println!("event={:?}", event);
                let token = event.token();
                if event.readiness().is_readable() {
                    match token {
                        SERVER_TOKEN => {
                            let client_socket = match self.socket.accept() {
                                Err(e) => {
                                    println!("Accept error: {}", e);
                                    return;
                                }
                                Ok((sock, _)) => sock,
                            };

                            self.token_counter += 1;
                            let new_token = mio::Token(self.token_counter);

                            self.clients
                                .insert(new_token, WebSocketClient::new(client_socket));
                            self.poll
                                .register(
                                    &self.clients[&new_token],
                                    new_token,
                                    mio::Ready::readable(),
                                    mio::PollOpt::edge() | mio::PollOpt::oneshot(),
                                )
                                .unwrap();
                        }
                        token => {
                            let mut client = self.clients.get_mut(&token).unwrap();
                            client.read();
                            self.poll
                                .reregister(
                                    &client.socket,
                                    token,
                                    client.interest,
                                    mio::PollOpt::edge() | mio::PollOpt::oneshot(),
                                )
                                .unwrap();
                        }
                    }
                }

                if event.readiness().is_writable() {
                    let client = self.clients.get_mut(&token).unwrap();
                    client.write();
                    println!("socket was writeable, interest now = {:?}", client.interest);
                    self.poll
                        .reregister(
                            &client.socket,
                            token,
                            client.interest,
                            mio::PollOpt::edge() | mio::PollOpt::oneshot(),
                        )
                        .unwrap();
                }

                if event.readiness().is_hup() {
                    let client = self.clients.remove(&token).unwrap();
                    client.socket.shutdown(std::net::Shutdown::Both).unwrap();
                    self.poll.deregister(&client.socket).unwrap();
                }
            }
        }
    }
}

fn main() {
    println!("Hello, world!");

    let address: SocketAddr = "0.0.0.0:10000".parse().unwrap();
    let server_socket = mio::net::TcpListener::bind(&address).unwrap();

    let mut server = WebSocketServer {
        token_counter: 0,
        clients: HashMap::new(),
        socket: server_socket,
        poll: mio::Poll::new().unwrap(),
        events: mio::Events::with_capacity(1024),
    };

    server.run();
}
