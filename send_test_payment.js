const Stellar = require("stellar-sdk");
const fetch = require("node-fetch");

(async function () {
  try {
    const server = new Stellar.Horizon.Server(
      "https://horizon-testnet.stellar.org",
    );
    const source = Stellar.Keypair.random();
    console.log("Source public:", source.publicKey());

    // Fund via friendbot
    console.log("Funding via friendbot...");
    const fbResp = await fetch(
      `https://friendbot.stellar.org?addr=${source.publicKey()}`,
    );
    if (!fbResp.ok) {
      throw new Error("Friendbot failed: " + fbResp.statusText);
    }
    console.log("Friendbot funded");

    // Ensure destination exists by funding it via friendbot (so payment op will succeed)
    const destination =
      "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP";
    console.log("Funding destination via friendbot (if needed)...");
    await fetch(`https://friendbot.stellar.org?addr=${destination}`);

    // Build & send 2 XLM
    const account = await server.loadAccount(source.publicKey());
    const tx = new Stellar.TransactionBuilder(account, {
      fee: Stellar.BASE_FEE,
      networkPassphrase: Stellar.Networks.TESTNET,
    })
      .addOperation(
        Stellar.Operation.payment({
          destination,
          asset: Stellar.Asset.native(),
          amount: "2",
        }),
      )
      .setTimeout(30)
      .build();

    tx.sign(source);
    const resp = await server.submitTransaction(tx);
    console.log("Submitted tx:", resp.hash);
  } catch (err) {
    console.error("Error:", err && err.toString ? err.toString() : err);
    process.exitCode = 1;
  }
})();
