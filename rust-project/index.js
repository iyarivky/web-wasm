import init from "./pkg/hello_world.js";

const runWasm = async () => {
  // Instantiate our wasm module
  const helloWorld = await init("./pkg/hello_world_bg.wasm");

  // Call the Add function export from wasm, save the result
  const addResult = helloWorld.add(123, 24);

  // Set the result onto the body
  document.body.textContent = `Hello World! addResult: ${addResult}`;
  console.log(`Hello World! addResult: ${addResult}`)
};
runWasm();