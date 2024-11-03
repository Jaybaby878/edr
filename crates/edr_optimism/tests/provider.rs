use std::{num::NonZeroU64, path::PathBuf};

use edr_defaults::CACHE_DIR;
use edr_eth::{
    address, bytes,
    signature::{secret_key_from_str, SecretKey},
    Address, BlockSpec, HashMap, U256, U64,
};
use edr_evm::MineOrdering;
use edr_optimism::{transaction, OptimismChainSpec, OptimismSpecId};
use edr_provider::{
    hardhat_rpc_types::ForkConfig,
    test_utils::{create_test_config_with_fork, ProviderTestFixture, TEST_SECRET_KEY},
    time::CurrentTime,
    AccountConfig, MemPoolConfig, MethodInvocation, MiningConfig, NoopLogger, Provider,
    ProviderConfig, ProviderRequest,
};
use edr_rpc_eth::CallRequest;
use edr_test_utils::env::get_alchemy_url;
use tokio::runtime;

const SEPOLIA_CHAIN_ID: u64 = 11_155_420;

fn sepolia_url() -> String {
    get_alchemy_url()
        .replace("eth-", "opt-")
        .replace("mainnet", "sepolia")
}

#[test]
fn sepolia_hardfork_activations() -> anyhow::Result<()> {
    const CANYON_BLOCK_NUMBER: u64 = 4_089_330;

    let url = sepolia_url();
    let fixture = ProviderTestFixture::<OptimismChainSpec>::new_forked(Some(url))?;

    let block_spec = BlockSpec::Number(CANYON_BLOCK_NUMBER);
    let (_, hardfork) = fixture
        .provider_data
        .create_evm_config_at_block_spec(&block_spec)?;

    assert_eq!(hardfork, OptimismSpecId::CANYON);

    let chain_id = fixture.provider_data.chain_id_at_block_spec(&block_spec)?;
    assert_eq!(chain_id, SEPOLIA_CHAIN_ID);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sepolia_call_with_remote_chain_id() -> anyhow::Result<()> {
    const GAS_PRICE_ORACLE_L1_BLOCK_ADDRESS: Address =
        address!("420000000000000000000000000000000000000F");

    let logger = Box::new(NoopLogger::<OptimismChainSpec>::default());
    let subscriber = Box::new(|_event| {});

    let mut config = create_test_config_with_fork(Some(ForkConfig {
        json_rpc_url: sepolia_url(),
        block_number: None,
        http_headers: None,
    }));

    // Set a different chain ID than the forked chain ID
    config.chain_id = 31337;

    let provider = Provider::new(
        runtime::Handle::current(),
        logger,
        subscriber,
        config,
        CurrentTime,
    )?;

    let last_block_number = {
        let response =
            provider.handle_request(ProviderRequest::Single(MethodInvocation::BlockNumber(())))?;

        serde_json::from_value::<U64>(response.result)?.to::<u64>()
    };

    let data = bytes!("de26c4a10000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002c02ea827a6981c4843b9aca00843b9c24e382520994f39fd6e51aad88f6f4ce6ab8827279cfffb922660180c00000000000000000000000000000000000000000");
    let _response = provider.handle_request(ProviderRequest::Single(MethodInvocation::Call(
        CallRequest {
            from: Some(address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266")),
            to: Some(GAS_PRICE_ORACLE_L1_BLOCK_ADDRESS),
            data: Some(data),
            ..CallRequest::default()
        },
        Some(BlockSpec::Number(last_block_number)),
        None,
    )))?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sepolia_call_with_error() -> anyhow::Result<()> {
    let logger = Box::new(NoopLogger::<OptimismChainSpec>::default());
    let subscriber = Box::new(|_event| {});

    // let mut config = create_test_config_with_fork(Some(ForkConfig {
    //     json_rpc_url: sepolia_url(),
    //     block_number: None,
    //     http_headers: None,
    // }));

    // let mut config = ProviderConfig { allow_blocks_with_same_timestamp: false, allow_unlimited_contract_size: false, accounts: [AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }, AccountConfig { secret_key: elliptic_curve::secret_key::SecretKey<k256::Secp256k1> { .. }, balance: 10000000000000000000000 }], bail_on_call_failure: true, bail_on_transaction_failure: true, block_gas_limit: 12500000, cache_dir: "/workspaces/hardhat/v-next/example-project/cache/edr-cache", chain_id: 10, chains: {}, coinbase: 0xc014ba5ec014ba5ec014ba5ec014ba5ec014ba5e, enable_rip_7212: false, fork: Some(ForkConfig { json_rpc_url: "https://mainnet.optimism.io", block_number: None, http_headers: None }), genesis_accounts: {}, hardfork: CANCUN, initial_base_fee_per_gas: None, initial_blob_gas: None, initial_date: None, initial_parent_beacon_block_root: None, min_gas_price: 0, mining: MiningConfig { auto_mine: true, interval: None, mem_pool: MemPoolConfig { order: Fifo } }, network_id: 10 };
    let config = ProviderConfig {
        allow_blocks_with_same_timestamp: false,
        allow_unlimited_contract_size: false,
        accounts: vec![AccountConfig {
            secret_key: secret_key_from_str(TEST_SECRET_KEY)
                .expect("should construct secret key from string"),
            balance: U256::from(10000000000000000000000u128),
        }],
        bail_on_call_failure: true,
        bail_on_transaction_failure: true,
        block_gas_limit: NonZeroU64::new(12500000).unwrap(),
        cache_dir: CACHE_DIR.into(),
        chain_id: 10,
        chains: HashMap::new(),
        coinbase: address!("c014ba5ec014ba5ec014ba5ec014ba5ec014ba5e"),
        enable_rip_7212: false,
        fork: Some(ForkConfig {
            json_rpc_url: "https://mainnet.optimism.io".to_string(),
            block_number: None,
            http_headers: None,
        }),
        genesis_accounts: HashMap::new(),
        hardfork: OptimismSpecId::CANCUN,
        initial_base_fee_per_gas: None,
        initial_blob_gas: None,
        initial_date: None,
        initial_parent_beacon_block_root: None,
        min_gas_price: U256::ZERO,
        mining: MiningConfig {
            auto_mine: true,
            interval: None,
            mem_pool: MemPoolConfig {
                order: MineOrdering::Fifo,
            },
        },
        network_id: 10,
    };

    // The default chain id set by Hardhat
    // config.chain_id = 31337;

    let provider = Provider::new(
        runtime::Handle::current(),
        logger,
        subscriber,
        config,
        CurrentTime,
    )?;

    // from: '0x2871e11949ae3f1b71850d2cb3ff25fbe892eda6',
    // maxFeePerGas: '0x3b9c1c46',
    // maxPriorityFeePerGas: '0x3b9aca00',
    // nonce: '0x18',
    // to: '0x2871e11949ae3f1b71850d2cb3ff25fbe892eda6',
    // value: '0x1'

    let _response =
        provider.handle_request(ProviderRequest::Single(MethodInvocation::EstimateGas(
            edr_rpc_eth::CallRequest {
                from: Some(address!("2871e11949ae3f1b71850d2cb3ff25fbe892eda6")),
                to: Some(address!("2871e11949ae3f1b71850d2cb3ff25fbe892eda6")),
                max_fee_per_gas: Some(U256::from(1_000_018_220)),
                max_priority_fee_per_gas: Some(U256::from(1_000_000_000)),
                // The default value is too high
                // gas: Some(21_000),
                ..edr_rpc_eth::CallRequest::default()
            },
            None,
        )))?;

    Ok(())
}
