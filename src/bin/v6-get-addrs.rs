
use ftthd::rtnl::RtnetlinkConnection;
use ftthd::rtnl::addr::V6AddressRequestScope;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let conn = RtnetlinkConnection::new().await?;
    let mut link_conn = conn.link();
    let addr_conn = conn.address();
    for iface in link_conn.get_all().await? {
        let link_local = addr_conn.get_v6(iface.if_index, V6AddressRequestScope::LinkLocal).await?;
        println!("Interface: {} ({}) {:?}", iface.if_name, iface.if_index, link_local);
    }

    let global = addr_conn.get_v6(0, V6AddressRequestScope::Global).await?;
    println!("Global IPv6 addresses: {:?}", global);
    Ok(())
}