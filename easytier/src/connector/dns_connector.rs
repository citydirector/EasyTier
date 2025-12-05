use std::{net::SocketAddr, sync::Arc};

use crate::{
    common::{
        dns::{resolve_txt_record, RESOLVER},
        error::Error,
        global_ctx::ArcGlobalCtx,
    },
    tunnel::{IpVersion, Tunnel, TunnelConnector, TunnelError, PROTO_PORT_OFFSET},
};
use anyhow::Context;
use dashmap::DashSet;
use hickory_resolver::proto::rr::rdata::SRV;
use rand::{seq::SliceRandom, Rng as _};

use crate::proto::common::TunnelInfo;

use super::{create_connector_by_url, http_connector::TunnelWithInfo};

/// 按照权重进行加权随机选择
fn weighted_choice<T>(options: &[(T, u64)]) -> Option<&T> {
    if options.is_empty() {
        return None;
    }
    
    let total_weight: u64 = options.iter().map(|(_, weight)| *weight).sum();
    
    // 如果总权重为0（所有记录权重都是0），则进行纯随机选择
    if total_weight == 0 {
        return options.choose(&mut rand::thread_rng()).map(|(item, _)| item);
    }

    let mut rng = rand::thread_rng();
    let rand_value = rng.gen_range(0..total_weight);
    let mut accumulated_weight = 0;

    for (item, weight) in options {
        accumulated_weight += *weight;
        if rand_value < accumulated_weight {
            return Some(item);
        }
    }

    // 理论上不应该走到这里，除非 options 为空
    options.last().map(|(item, _)| item)
}

#[derive(Debug)]
pub struct DNSTunnelConnector {
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
    global_ctx: ArcGlobalCtx,
    ip_version: IpVersion,
}

impl DNSTunnelConnector {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            addr,
            bind_addrs: Vec::new(),
            global_ctx,
            ip_version: IpVersion::Both,
        }
    }

    #[tracing::instrument(ret, err)]
    pub async fn handle_txt_record(
        &self,
        domain_name: &str,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        let txt_data = resolve_txt_record(domain_name)
            .await
            .with_context(|| format!("resolve txt record failed, domain_name: {}", domain_name))?;

        let candidate_urls = txt_data
            .split(" ")
            .map(|s| s.to_string())
            .filter_map(|s| url::Url::parse(s.as_str()).ok())
            .collect::<Vec<_>>();

        // TXT 记录没有权重概念，随机选择一个
        let url = candidate_urls
            .choose(&mut rand::thread_rng())
            .with_context(|| {
                format!(
                    "no valid url found, txt_data: {}, expecting an url list splitted by space",
                    txt_data
                )
            })?;

        let connector =
            create_connector_by_url(url.as_str(), &self.global_ctx, self.ip_version).await?;
        Ok(connector)
    }

    /// 解析单个 SRV 记录，返回 (TargetUrl, Priority, Weight)
    fn handle_one_srv_record(record: &SRV, protocol: &str) -> Result<(url::Url, u16, u16), Error> {
        // port must be non-zero
        if record.port() == 0 {
            return Err(anyhow::anyhow!("port must be non-zero").into());
        }

        let connector_dst = record.target().to_utf8();
        // DNS 记录通常以 . 结尾，构造 URL 时最好去掉
        let connector_dst = connector_dst.trim_end_matches('.');
        
        let dst_url = format!("{}://{}:{}", protocol, connector_dst, record.port());

        Ok((
            dst_url.parse().with_context(|| {
                format!(
                    "parse dst_url failed, protocol: {}, connector_dst: {}, port: {}, dst_url: {}",
                    protocol,
                    connector_dst,
                    record.port(),
                    dst_url
                )
            })?,
            record.priority(),
            record.weight(),
        ))
    }

    #[tracing::instrument(ret, err)]
    pub async fn handle_srv_record(
        &self,
        domain_name: &str,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        tracing::info!("handle_srv_record: {}", domain_name);

        // 构造要查询的 SRV 域名
        let srv_domains = PROTO_PORT_OFFSET
            .iter()
            .map(|(p, _)| (format!("_easytier._{}.{}", p, domain_name), *p))
            .collect::<Vec<_>>();
        
        tracing::info!("build srv_domains: {:?}", srv_domains);
        
        // 使用 DashSet 收集结果，自动去重
        // 存储结构: (Url, Priority, Weight)
        let responses = Arc::new(DashSet::new());
        
        let srv_lookup_tasks = srv_domains
            .iter()
            .map(|(srv_domain, protocol)| {
                let resolver = RESOLVER.clone();
                let responses = responses.clone();
                async move {
                    if let Ok(response) = resolver.srv_lookup(srv_domain).await {
                        tracing::info!(?response, ?srv_domain, "srv_lookup response");
                        for record in response.iter() {
                            let parsed_record = Self::handle_one_srv_record(record, protocol);
                            tracing::info!(?parsed_record, ?srv_domain, "parsed_record");
                            if let Ok(r) = parsed_record {
                                responses.insert(r);
                            }
                        }
                    } else {
                         tracing::debug!("srv_lookup failed or empty for {}", srv_domain);
                    }
                    Ok::<_, Error>(())
                }
            })
            .collect::<Vec<_>>();
        
        let _ = futures::future::join_all(srv_lookup_tasks).await;

        if responses.is_empty() {
            return Err(anyhow::anyhow!("no srv record found").into());
        }

        // 将结果转为 Vec 以便排序
        let mut srv_records: Vec<_> = responses.iter().map(|r| r.clone()).collect();

        // 1. 按照 Priority 升序排序 (数值越小优先级越高)
        srv_records.sort_by_key(|(_, priority, _)| *priority);

        // 2. 获取优先级最高（Priority 最小）的那一组记录
        let best_priority = srv_records[0].1;
        let best_priority_records: Vec<_> = srv_records
            .iter()
            .filter(|(_, p, _)| *p == best_priority)
            .collect();

        // 3. 在同优先级的记录中，根据 Weight 进行加权随机选择
        let candidates: Vec<(&url::Url, u64)> = best_priority_records
            .iter()
            .map(|(u, _, w)| (u, *w as u64))
            .collect();

        let url = weighted_choice(&candidates).with_context(|| {
            format!(
                "failed to choose a srv record, domain_name: {}, candidates: {:?}",
                domain_name, candidates
            )
        })?;

        tracing::info!("selected srv target: {}", url);

        let connector =
            create_connector_by_url(url.as_str(), &self.global_ctx, self.ip_version).await?;
        Ok(connector)
    }
}

#[async_trait::async_trait]
impl super::TunnelConnector for DNSTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let mut conn = if self.addr.scheme() == "txt" {
            self.handle_txt_record(
                self.addr
                    .host_str()
                    .as_ref()
                    .ok_or(anyhow::anyhow!("host should not be empty in txt url"))?,
            )
            .await
            .with_context(|| "get txt record url failed")?
        } else if self.addr.scheme() == "srv" {
            self.handle_srv_record(
                self.addr
                    .host_str()
                    .as_ref()
                    .ok_or(anyhow::anyhow!("host should not be empty in srv url"))?,
            )
            .await
            .with_context(|| "get srv record url failed")?
        } else {
            return Err(anyhow::anyhow!(
                "unsupported dns scheme: {}, expecting txt or srv",
                self.addr.scheme()
            )
            .into());
        };

        conn.set_ip_version(self.ip_version);
        conn.set_bind_addrs(self.bind_addrs.clone());

        let t = conn.connect().await?;
        let info = t.info().unwrap_or_default();
        Ok(Box::new(TunnelWithInfo::new(
            t,
            TunnelInfo {
                local_addr: info.local_addr.clone(),
                remote_addr: Some(self.addr.clone().into()),
                tunnel_type: format!(
                    "{}-{}",
                    self.addr.scheme(),
                    info.remote_addr.unwrap_or_default()
                ),
            },
        )))
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::global_ctx::tests::get_mock_global_ctx;

    #[tokio::test]
    async fn test_txt() {
        let url = "txt://txt.easytier.cn";
        let global_ctx = get_mock_global_ctx();
        let mut connector = DNSTunnelConnector::new(url.parse().unwrap(), global_ctx);
        connector.set_ip_version(IpVersion::V4);
        if let Err(e) = connector.connect().await {
            println!("test_txt connect result: {:?}", e);
        }
    }

    #[tokio::test]
    async fn test_srv() {
        let url = "srv://easytier.cn";
        let global_ctx = get_mock_global_ctx();
        let mut connector = DNSTunnelConnector::new(url.parse().unwrap(), global_ctx);
        connector.set_ip_version(IpVersion::V4);
        if let Err(e) = connector.connect().await {
            println!("test_srv connect result: {:?}", e);
        }
    }
}