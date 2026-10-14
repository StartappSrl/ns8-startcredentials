chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (sender.id !== chrome.runtime.id || msg?.type !== "offscreen-clear") return;
  const t = document.getElementById("clip") as HTMLTextAreaElement;
  t.value = " ";
  t.select();
  document.execCommand("copy");
  reply(true);
  return true;
});
