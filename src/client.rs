use async_ssh2_tokio::client::CommandExecutedResult;
use async_trait::async_trait;
use russh::{
    client,
    keys::{self, key},
};
use std::{net, sync};
use tokio::io::AsyncWriteExt;
/// [async_ssh2_tokio::client::Client]
pub struct Client {
    handle: client::Handle<ClientHandler>,
}
impl Client {
    /// [async_ssh2_tokio::client::Client::connect]
    pub async fn connect(
        addr: impl async_ssh2_tokio::ToSocketAddrsWithHostname,
        username: &str,
        auth: async_ssh2_tokio::AuthMethod,
        server_check: async_ssh2_tokio::ServerCheckMethod,
    ) -> Result<Self, async_ssh2_tokio::Error> {
        let config = sync::Arc::new(client::Config::default());
        let socket_addr = addr.to_socket_addrs().unwrap()[0];
        let mut handle = russh::client::connect(
            config.clone(),
            socket_addr,
            ClientHandler {
                hostname: addr.hostname(),
                port: socket_addr.port(),
                server_check,
            },
        )
        .await
        .unwrap();
        match auth {
            async_ssh2_tokio::AuthMethod::Password(password) => {
                if !handle.authenticate_password(username, password).await? {
                    return Err(async_ssh2_tokio::Error::PasswordWrong);
                }
            }
            _ => todo!(),
        }
        Ok(Self { handle })
    }
    /// [async_ssh2_tokio::client::Client::open_direct_tcpip_channel]
    pub async fn open_direct_tcpip_channel<
        T: async_ssh2_tokio::ToSocketAddrsWithHostname,
        S: Into<Option<net::SocketAddr>>,
    >(
        &self,
        target: T,
        src: S,
    ) -> Result<russh::Channel<client::Msg>, async_ssh2_tokio::Error> {
        let target = target.to_socket_addrs().unwrap()[0];
        let src: net::SocketAddr = src.into().unwrap();
        Ok(self
            .handle
            .channel_open_direct_tcpip(
                target.ip().to_string(),
                target.port().into(),
                src.ip().to_string().clone(),
                src.port().into(),
            )
            .await
            .unwrap())
    }
    /// [async_ssh2_tokio::client::Client::execute]
    pub async fn execute(
        &self,
        command: &str,
    ) -> Result<CommandExecutedResult, async_ssh2_tokio::Error> {
        let mut stdout = vec![];
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, command).await?;
        let mut res: Option<u32> = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => stdout.write_all(data).await.unwrap(),
                russh::ChannelMsg::ExitStatus { exit_status } => res = Some(exit_status),
                _ => {}
            }
        }
        Ok(CommandExecutedResult {
            stdout: String::from_utf8(stdout).unwrap(),
            stderr: String::from_utf8(vec![]).unwrap(),
            exit_status: res.unwrap(),
        })
    }
    /// [async_ssh2_tokio::client::Client::disconnect]
    pub async fn disconnect(&self) -> Result<(), async_ssh2_tokio::Error> {
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .map_err(async_ssh2_tokio::Error::SshError)
    }
}
struct ClientHandler {
    hostname: String,
    port: u16,
    server_check: async_ssh2_tokio::ServerCheckMethod,
}
#[async_trait]
impl client::Handler for ClientHandler {
    type Error = async_ssh2_tokio::Error;
    async fn check_server_key(
        &mut self,
        server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        match &self.server_check {
            async_ssh2_tokio::ServerCheckMethod::NoCheck => Ok(true),
            async_ssh2_tokio::ServerCheckMethod::PublicKeyFile(key_file_name) => {
                Ok(keys::load_public_key(key_file_name)
                    .map_err(|_| async_ssh2_tokio::Error::ServerCheckFailed)?
                    == *server_public_key)
            }
            async_ssh2_tokio::ServerCheckMethod::DefaultKnownHostsFile => Ok(
                keys::check_known_hosts(&self.hostname, self.port, server_public_key)
                    .map_err(|_| async_ssh2_tokio::Error::ServerCheckFailed)?,
            ),
            _ => todo!(),
        }
    }
}
