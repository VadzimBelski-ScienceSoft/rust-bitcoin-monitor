extern crate bitcoincore_rpc;
extern crate serde_json;
extern crate ticker;
extern crate log;
extern crate jsonrpc;

use std::time::Duration;
use bitcoincore_rpc::{Client, Auth, RpcApi};
use ticker::Ticker;

fn main() {

    env_logger::init();

    let rpc = Client::new("http://127.0.0.1:10003",
                          Auth::UserPass("user".to_string(),
                                         "user".to_string())).unwrap();

    let ticker = Ticker::new(0.., Duration::from_secs(5));

    let block_count = rpc.get_block_count().unwrap();
    println!("block count: {}", block_count);
        
    let mut next_block = rpc.get_block_hash(block_count).unwrap();
    let mut latest_scanned_block : String = "".to_string();

    for _ in ticker {
 
        println!("We are on the block {}", next_block);

        let block = rpc.get_block_info(&next_block).unwrap();
        
        if latest_scanned_block != block.hash.to_string() {
            for tx in &block.tx {
                scan_transaction(&tx, &rpc);
                latest_scanned_block = block.hash.to_string();
            }
        }
        // Lets got to next transaction only after 2 confirmations ?
        if  block.nextblockhash != None && block.confirmations >= 2 {
            println!("{}", serde_json::to_string_pretty(&block).unwrap());
            next_block = block.nextblockhash.unwrap();
        }else{
            println!("No more blocks");
        }            
    
    }

}

fn scan_transaction(tx: &bitcoincore_rpc::bitcoin::Txid, rpc: &bitcoincore_rpc::Client) {

    let raw_transaction_hex = rpc.get_raw_transaction_hex(&tx, None).unwrap();
    let args = [serde_json::to_value(&raw_transaction_hex).unwrap(), true.into()];

    let result : serde_json::Value =  rpc.call("decoderawtransaction", &args ).unwrap();
    let json_object = result.as_object().unwrap();

    for index in json_object["vout"].as_array().unwrap() {
        println!("Result : {:#?}", index["scriptPubKey"]["addresses"][0]);
    }
}