// ObfuscatorHub — Lua Syntax Highlighter
(function() {

const LUA_KEYWORDS = [
  "and","break","do","else","elseif","end","false","for","function",
  "goto","if","in","local","nil","not","or","repeat","return","then",
  "true","until","while"
];

const LUA_BUILTINS = [
  "print","warn","error","tostring","tonumber","type","pairs","ipairs",
  "next","select","unpack","rawget","rawset","rawequal","rawlen",
  "setmetatable","getmetatable","require","load","loadstring","pcall",
  "xpcall","coroutine","table","string","math","os","io","debug",
  "assert","collectgarbage","dofile","loadfile","module","package",
  "rawlen","rawset","rawget"
];

const ROBLOX_GLOBALS = [
  "game","workspace","script","plugin","shared","_G",
  "Instance","Vector3","Vector2","CFrame","Color3","BrickColor",
  "UDim","UDim2","Ray","Rect","Region3","TweenInfo","Enum",
  "RunService","Players","Workspace","ReplicatedStorage","ServerStorage",
  "ServerScriptService","StarterGui","StarterPack","StarterPlayer",
  "Lighting","Teams","SoundService","UserInputService","GuiService",
  "TweenService","HttpService","DataStoreService","MessagingService",
  "PhysicsService","CollectionService","ContextActionService",
  "task","wait","spawn","delay","tick","time","elapsedTime",
  "loadstring","hookfunction","hookmetamethod","newcclosure",
  "ishooked","isfunctionhooked","restorefunction","setreadonly",
  "getrawmetatable","setrawmetatable","getgenv","getrenv","getsenv",
  "getfenv","setfenv","getnamecallmethod","setnamecallmethod",
  "checkcaller","isexecutorclosure","clonefunction","islclosure",
  "setclipboard","getclipboard","writefile","readfile","listfiles",
  "request","HttpGet","HttpPost","mousemoverel","mousemoveabs",
  "mouse1click","mouse2click","keypress","keyrelease"
];

const THEME = {
  bg:       "#0a0a12",
  text:     "#e0e8ff",
  keyword:  "#ff79c6",
  builtin:  "#8be9fd",
  roblox:   "#50fa7b",
  string:   "#f1fa8c",
  number:   "#bd93f9",
  comment:  "#6272a4",
  operator: "#ff79c6",
  bracket:  "#f8f8f2",
  linenum:  "#44475a",
  cursor:   "#00f5ff",
};

function escapeHtml(t) {
  return t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function tokenize(line) {
  let result = "", i = 0;
  const len = line.length;
  while (i < len) {
    if (line[i]==="-"&&line[i+1]==="-") {
      result+=`<span style="color:${THEME.comment}">${escapeHtml(line.slice(i))}</span>`; break;
    }
    if (line[i]==='"') {
      let j=i+1; while(j<len&&(line[j]!=='"'||line[j-1]==="\\"))j++; j++;
      result+=`<span style="color:${THEME.string}">${escapeHtml(line.slice(i,j))}</span>`; i=j; continue;
    }
    if (line[i]==="'") {
      let j=i+1; while(j<len&&(line[j]!=="'"||line[j-1]==="\\"))j++; j++;
      result+=`<span style="color:${THEME.string}">${escapeHtml(line.slice(i,j))}</span>`; i=j; continue;
    }
    if (line[i]==="["&&line[i+1]==="[") {
      let j=i+2; while(j<len-1&&!(line[j]==="]"&&line[j+1]==="]"))j++; j+=2;
      result+=`<span style="color:${THEME.string}">${escapeHtml(line.slice(i,j))}</span>`; i=j; continue;
    }
    if (/[0-9]/.test(line[i])||(line[i]==="."&&/[0-9]/.test(line[i+1]||""))) {
      let j=i;
      if(line[i]==="0"&&(line[i+1]==="x"||line[i+1]==="X")){j+=2;while(j<len&&/[0-9a-fA-F]/.test(line[j]))j++;}
      else{while(j<len&&/[0-9._eE]/.test(line[j]))j++;}
      result+=`<span style="color:${THEME.number}">${escapeHtml(line.slice(i,j))}</span>`; i=j; continue;
    }
    if (/[a-zA-Z_]/.test(line[i])) {
      let j=i; while(j<len&&/[a-zA-Z0-9_]/.test(line[j]))j++;
      const w=line.slice(i,j);
      if(LUA_KEYWORDS.includes(w)) result+=`<span style="color:${THEME.keyword};font-weight:600">${escapeHtml(w)}</span>`;
      else if(ROBLOX_GLOBALS.includes(w)) result+=`<span style="color:${THEME.roblox}">${escapeHtml(w)}</span>`;
      else if(LUA_BUILTINS.includes(w)) result+=`<span style="color:${THEME.builtin}">${escapeHtml(w)}</span>`;
      else result+=escapeHtml(w);
      i=j; continue;
    }
    if ("()[]{}".includes(line[i])){result+=`<span style="color:${THEME.bracket}">${escapeHtml(line[i])}</span>`;i++;continue;}
    if ("=+-*/%^#<>~&|".includes(line[i])){result+=`<span style="color:${THEME.operator}">${escapeHtml(line[i])}</span>`;i++;continue;}
    result+=escapeHtml(line[i]); i++;
  }
  return result;
}

function highlight(code) {
  let inMLComment=false, inMLString=false;
  return code.split("\n").map(line => {
    let result="";
    if (inMLComment) {
      const end=line.indexOf("]]");
      if(end!==-1){result=`<span style="color:${THEME.comment}">${escapeHtml(line.slice(0,end+2))}</span>`+tokenize(line.slice(end+2));inMLComment=false;}
      else result=`<span style="color:${THEME.comment}">${escapeHtml(line)}</span>`;
    } else if (inMLString) {
      const end=line.indexOf("]]");
      if(end!==-1){result=`<span style="color:${THEME.string}">${escapeHtml(line.slice(0,end+2))}</span>`+tokenize(line.slice(end+2));inMLString=false;}
      else result=`<span style="color:${THEME.string}">${escapeHtml(line)}</span>`;
    } else {
      const mlc=line.indexOf("--[[");
      if(mlc!==-1&&line.indexOf("]]",mlc+4)===-1){
        result=tokenize(line.slice(0,mlc))+`<span style="color:${THEME.comment}">${escapeHtml(line.slice(mlc))}</span>`;
        inMLComment=true;
      } else {
        result=tokenize(line);
      }
    }
    return result;
  });
}

function initHighlighter(textareaId) {
  const ta = document.getElementById(textareaId);
  if (!ta) return null;
  if (ta._hlInstance) return ta._hlInstance;

  const placeholderText = ta.getAttribute("placeholder") || "";
  ta.removeAttribute("placeholder");

  // Read the textarea's intended height — prefer an inline style if set,
  // otherwise fall back to a fixed value matching this page's own
  // min-height:240px design. (We can't use getComputedStyle here: this
  // textarea sits inside the editor panel, which is display:none until the
  // user unlocks, and a display:none element's computed height is always
  // "0px" since it has no rendered box — that's what collapsed the box.)
  const taHeight = ta.style.height || "240px";

  // ── Wrapper — simple position:relative, NO flexbox ────────────────────────
  const wrapper = document.createElement("div");
  wrapper.style.cssText = `
    position: relative;
    border-radius: 10px;
    overflow: hidden;
    border: 1px solid rgba(0,245,255,0.15);
    transition: border-color 0.3s, box-shadow 0.3s;
    background: ${THEME.bg};
    height: ${taHeight};
    box-sizing: border-box;
  `;

  // ── Line numbers (absolute, left side) ───────────────────────────────────
  // Outer clips the inner; inner slides via margin-top.
  const lineNumsOuter = document.createElement("div");
  lineNumsOuter.style.cssText = `
    position: absolute;
    top: 0; left: 0; bottom: 0;
    width: 44px;
    overflow: hidden;
    border-right: 1px solid rgba(255,255,255,0.06);
    background: ${THEME.bg};
    z-index: 2;
    user-select: none;
    pointer-events: none;
  `;

  const lineNumsInner = document.createElement("div");
  lineNumsInner.style.cssText = `
    margin-top: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    line-height: 1.7;
    text-align: right;
    color: ${THEME.linenum};
  `;
  lineNumsOuter.appendChild(lineNumsInner);

  // ── Highlight mirror (absolute, behind textarea) ──────────────────────────
  const hlDiv = document.createElement("div");
  hlDiv.style.cssText = `
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    padding: 12px 14px 12px 52px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    line-height: 1.7;
    white-space: pre;
    overflow: hidden;
    pointer-events: none;
    color: ${THEME.text};
    tab-size: 2;
    box-sizing: border-box;
    z-index: 1;
  `;

  // ── Placeholder ───────────────────────────────────────────────────────────
  const placeholderEl = document.createElement("div");
  placeholderEl.style.cssText = `
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    padding: 12px 14px 12px 52px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    line-height: 1.7;
    color: rgba(0,255,136,0.25);
    pointer-events: none;
    white-space: pre-wrap;
    box-sizing: border-box;
    z-index: 3;
    display: none;
  `;
  placeholderEl.textContent = placeholderText;

  // ── Textarea — fills the wrapper absolutely ───────────────────────────────
  ta.style.cssText = `
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    z-index: 4;
    width: 100%;
    height: 100%;
    background: transparent !important;
    border: none;
    border-radius: 0;
    color: transparent;
    caret-color: ${THEME.cursor};
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    line-height: 1.7;
    padding: 12px 14px 12px 52px;
    white-space: pre;
    overflow: auto;
    resize: none;
    outline: none;
    box-sizing: border-box;
    tab-size: 2;
  `;

  // Assemble — insert wrapper before textarea, then move ta inside
  ta.parentNode.insertBefore(wrapper, ta);
  wrapper.appendChild(lineNumsOuter);
  wrapper.appendChild(hlDiv);
  wrapper.appendChild(placeholderEl);
  wrapper.appendChild(ta);

  // Focus glow
  ta.addEventListener("focus", () => {
    wrapper.style.borderColor = "var(--cyan,#00f5ff)";
    wrapper.style.boxShadow   = "0 0 20px rgba(0,245,255,0.2)";
  });
  ta.addEventListener("blur", () => {
    wrapper.style.borderColor = "rgba(0,245,255,0.15)";
    wrapper.style.boxShadow   = "none";
  });

  // Scroll sync: shift lineNumsInner up by scrollTop using margin-top
  // margin-top = 12 - scrollTop  (negative margin is valid CSS, unlike padding)
  //
  // hlDiv is synced by *percentage*, not raw pixels. The real textarea and the
  // highlight div are two independently-rendered elements; if their content
  // heights ever drift by even a few px (rounding, a trailing blank line,
  // box-model differences), pixel-for-pixel syncing makes hlDiv hit its own
  // max scroll slightly before ta does — so scrolling to the very end of a
  // long script would freeze the colored backdrop a line or two early while
  // the (invisible, transparent-text) textarea keeps going, making the last
  // lines look blank. Percentage sync guarantees both reach 0% and 100% together.
  function syncScroll() {
    lineNumsInner.style.marginTop = (12 - ta.scrollTop) + "px";

    const taMax = ta.scrollHeight - ta.clientHeight;
    const pct   = taMax > 0 ? ta.scrollTop / taMax : 0;
    const hlMax = hlDiv.scrollHeight - hlDiv.clientHeight;

    hlDiv.scrollTop  = pct * hlMax;
    hlDiv.scrollLeft = ta.scrollLeft;
  }

  function update() {
    const code  = ta.value;
    const lines = highlight(code);
    const LH    = 12 * 1.7; // 20.4px

    placeholderEl.style.display = code.length === 0 ? "block" : "none";

    // Line numbers — each div is exactly one line tall
    let nums = "";
    for (let i = 1; i <= lines.length; i++) {
      nums += `<div style="height:${LH}px;line-height:${LH}px;padding-right:8px">${i}</div>`;
    }
    lineNumsInner.innerHTML = nums;

    hlDiv.innerHTML = lines.join("\n");

    syncScroll();
  }

  ta.addEventListener("input",  update);
  ta.addEventListener("scroll", syncScroll);

  ta.addEventListener("keydown", e => {
    if (e.key === "Tab") {
      e.preventDefault();
      const s = ta.selectionStart, en = ta.selectionEnd;
      ta.value = ta.value.slice(0,s) + "  " + ta.value.slice(en);
      ta.selectionStart = ta.selectionEnd = s + 2;
      update();
    }
  });

  update();

  const instance = { update, wrapper };
  ta._hlInstance = instance;
  return instance;
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("textarea[data-lua-highlight]").forEach(ta => {
    initHighlighter(ta.id);
  });
});

window.LuaHighlight = { init: initHighlighter };

})();
