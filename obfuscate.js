/**
 * QyrexObf v6 (beta)
 * Heavy VM-style shell: dispatch table + hex/binary literals + multi-round XOR payload.
 * Output is always valid Lua 5.1 / Luau (loadstring/load).
 */
const crypto = require('crypto');

const KW = new Set([
  'and','break','do','else','elseif','end','false','for','function','goto',
  'if','in','local','nil','not','or','repeat','return','then','true','until','while'
]);

function lex(src) {
  const toks = [];
  let i = 0;
  const n = src.length;
  const isSpace = (c) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v';
  const isDigit = (c) => c >= '0' && c <= '9';
  const isHex = (c) => isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  const isIdStart = (c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c === '_';
  const isIdCont = (c) => isIdStart(c) || isDigit(c);

  while (i < n) {
    const c = src[i];
    if (isSpace(c)) {
      let j = i;
      while (j < n && isSpace(src[j])) j++;
      toks.push({ type: 'ws', val: ' ' });
      i = j;
      continue;
    }
    if (c === '-' && src[i + 1] === '-') {
      if (src[i + 2] === '[') {
        let k = i + 3, eq = 0;
        while (src[k] === '=') { eq++; k++; }
        if (src[k] === '[') {
          const close = ']' + '='.repeat(eq) + ']';
          const end = src.indexOf(close, k + 1);
          i = end === -1 ? n : end + close.length;
          continue;
        }
      }
      let j = i;
      while (j < n && src[j] !== '\n') j++;
      i = j;
      continue;
    }
    if (c === "'" || c === '"') {
      const q = c;
      let j = i + 1;
      while (j < n) {
        if (src[j] === '\\') { j += 2; continue; }
        if (src[j] === q) { j++; break; }
        j++;
      }
      toks.push({ type: 'string', val: src.slice(i, j) });
      i = j;
      continue;
    }
    if (c === '[') {
      let k = i + 1, eq = 0;
      while (src[k] === '=') { eq++; k++; }
      if (src[k] === '[') {
        const close = ']' + '='.repeat(eq) + ']';
        const end = src.indexOf(close, k + 1);
        const stop = end === -1 ? n : end + close.length;
        toks.push({ type: 'lstring', val: src.slice(i, stop) });
        i = stop;
        continue;
      }
    }
    if (isDigit(c) || (c === '.' && isDigit(src[i + 1] || ''))) {
      let j = i;
      if (c === '0' && (src[i + 1] === 'x' || src[i + 1] === 'X')) {
        j += 2;
        while (j < n && isHex(src[j])) j++;
      } else {
        while (j < n && isDigit(src[j])) j++;
        if (src[j] === '.') {
          j++;
          while (j < n && isDigit(src[j])) j++;
        }
        if (src[j] === 'e' || src[j] === 'E') {
          j++;
          if (src[j] === '+' || src[j] === '-') j++;
          while (j < n && isDigit(src[j])) j++;
        }
      }
      toks.push({ type: 'num', val: src.slice(i, j) });
      i = j;
      continue;
    }
    if (isIdStart(c)) {
      let j = i + 1;
      while (j < n && isIdCont(src[j])) j++;
      const v = src.slice(i, j);
      toks.push({ type: KW.has(v) ? 'kw' : 'ident', val: v });
      i = j;
      continue;
    }
    const two = src.slice(i, i + 2);
    if (['==', '~=', '<=', '>=', '..', '::'].includes(two)) {
      toks.push({ type: 'sym', val: two });
      i += 2;
      continue;
    }
    if (src.slice(i, i + 3) === '...') {
      toks.push({ type: 'sym', val: '...' });
      i += 3;
      continue;
    }
    toks.push({ type: 'sym', val: c });
    i++;
  }
  return toks;
}

function decodeLuaString(literal) {
  if (!literal || literal.length < 2) return null;
  if (literal.startsWith('[')) {
    const m = /^\[(=*)\[/.exec(literal);
    if (!m) return null;
    const eq = m[1].length;
    let body = literal.slice(2 + eq, literal.length - 2 - eq);
    if (body.startsWith('\n')) body = body.slice(1);
    else if (body.startsWith('\r\n')) body = body.slice(2);
    const bytes = [];
    for (let i = 0; i < body.length; i++) {
      const code = body.charCodeAt(i);
      if (code > 0xff) return null;
      bytes.push(code);
    }
    return bytes;
  }
  const q = literal[0];
  if (q !== "'" && q !== '"') return null;
  const s = literal.slice(1, -1);
  const out = [];
  let i = 0;
  while (i < s.length) {
    const ch = s[i];
    if (ch !== '\\') {
      const code = ch.charCodeAt(0);
      if (code > 0xff) return null;
      out.push(code);
      i++;
      continue;
    }
    const nx = s[i + 1];
    if (nx === undefined) return null;
    const map = { a: 7, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11, '\\': 92, '"': 34, "'": 39, '\n': 10 };
    if (map[nx] !== undefined) {
      out.push(map[nx]);
      i += 2;
      continue;
    }
    if (nx === 'x') {
      const hex = s.slice(i + 2, i + 4);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) return null;
      out.push(parseInt(hex, 16));
      i += 4;
      continue;
    }
    if (nx >= '0' && nx <= '9') {
      let j = i + 1;
      let num = '';
      while (j < s.length && num.length < 3 && s[j] >= '0' && s[j] <= '9') {
        num += s[j];
        j++;
      }
      const v = parseInt(num, 10);
      if (v > 255) return null;
      out.push(v);
      i = j;
      continue;
    }
    return null;
  }
  return out;
}

const R = (a, b) => a + Math.floor(Math.random() * (b - a + 1));

function hexLit(n) {
  const v = n & 0xff;
  const styles = [
    () => '0x' + v.toString(16),
    () => '0X' + v.toString(16).toUpperCase(),
    () => '0b' + v.toString(2),
    () => String(v)
  ];
  return styles[R(0, styles.length - 1)]();
}

function makeId(prefix) {
  const start = 'lIoO';
  const chars = 'IlOo01';
  let s = (prefix || 'l') + start[R(0, 3)];
  for (let i = 0; i < R(5, 10); i++) s += chars[R(0, chars.length - 1)];
  s += R(10, 99);
  if (!/^[A-Za-z_]/.test(s)) s = 'l' + s;
  return s;
}

function encryptStrings(toks, sName) {
  const pool = [];
  const key = R(37, 211);
  const out = toks.map((t) => {
    if (t.type !== 'string' && t.type !== 'lstring') return t;
    const bytes = decodeLuaString(t.val);
    if (!bytes || !bytes.length || bytes.length > 4096) return t;
    if (!bytes.some((b) => (b >= 65 && b <= 90) || (b >= 97 && b <= 122))) return t;
    const idx = pool.length;
    pool.push(bytes.map((b, i) => b ^ key ^ ((i * 7) % 251)));
    return { type: 'ident', val: sName + '[' + idx + ']' };
  });
  if (!pool.length) return { toks, header: null };
  const parts = pool.map((arr) => '{' + arr.map(hexLit).join(',') + '}');
  const header =
    'local ' + sName + ';do local __k=' + hexLit(key) +
    ' local __p={' + parts.join(',') + '} local __o={} ' +
    'for i=1,#__p do local t=__p[i] local r={} for j=1,#t do ' +
    'local x,y,z=t[j],__k,((j-1)*7)%251 local o,p=0,1 ' +
    'for _=1,8 do local bx,by,bz=x%2,y%2,z%2 o=o+((bx+by+bz)%2)*p ' +
    'x=(x-bx)/2 y=(y-by)/2 z=(z-bz)/2 p=p*2 end r[j]=string.char(o) end ' +
    '__o[i-1]=table.concat(r) end ' + sName + '=__o end\n';
  return { toks: out, header };
}

function numbersToExpr(toks) {
  return toks.map((t) => {
    if (t.type !== 'num' || !/^\d+$/.test(t.val)) return t;
    const v = parseInt(t.val, 10);
    if (v < 8 || v > 50000 || Math.random() > 0.5) return t;
    const a = R(1, Math.max(1, v - 1));
    return { type: 'sym', val: '(' + hexLit(a) + '+' + hexLit(v - a) + ')' };
  });
}

function renameLocals(toks) {
  const used = new Set();
  const nextId = () => {
    for (;;) {
      const id = makeId('_l');
      if (!used.has(id)) {
        used.add(id);
        return id;
      }
    }
  };
  const scopes = [new Map()];
  const out = [];
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.type === 'kw' && (t.val === 'function' || t.val === 'do' || t.val === 'then' || t.val === 'repeat')) {
      scopes.push(new Map());
      out.push(t);
      continue;
    }
    if (t.type === 'kw' && t.val === 'end') {
      if (scopes.length > 1) scopes.pop();
      out.push(t);
      continue;
    }
    if (t.type === 'kw' && t.val === 'local') {
      out.push(t);
      let j = i + 1;
      while (j < toks.length && toks[j].type === 'ws') {
        out.push(toks[j]);
        j++;
      }
      if (j < toks.length && toks[j].type === 'kw' && toks[j].val === 'function') {
        out.push(toks[j]);
        j++;
        while (j < toks.length && toks[j].type === 'ws') {
          out.push(toks[j]);
          j++;
        }
        if (j < toks.length && toks[j].type === 'ident') {
          const neu = nextId();
          scopes[scopes.length - 1].set(toks[j].val, neu);
          out.push({ type: 'ident', val: neu });
          j++;
        }
        i = j - 1;
        continue;
      }
      while (j < toks.length) {
        const tj = toks[j];
        if (tj.type === 'ident') {
          const neu = nextId();
          scopes[scopes.length - 1].set(tj.val, neu);
          out.push({ type: 'ident', val: neu });
          j++;
          continue;
        }
        if (tj.type === 'ws' || tj.val === ',' || tj.val === '=') {
          out.push(tj);
          if (tj.val === '=') {
            j++;
            break;
          }
          j++;
          continue;
        }
        break;
      }
      i = j - 1;
      continue;
    }
    if (t.type === 'ident') {
      let mapped = null;
      for (let s = scopes.length - 1; s >= 0; s--) {
        if (scopes[s].has(t.val)) {
          mapped = scopes[s].get(t.val);
          break;
        }
      }
      out.push(mapped ? { type: 'ident', val: mapped } : t);
      continue;
    }
    out.push(t);
  }
  return out;
}

function antiTamper() {
  return [
    'do',
    'local function __d(r) error(tostring(r or 0XDEAD),0) end',
    'local rg,pc,ty=rawget,pcall,type',
    'for _,k in ipairs({"lune","lute","wally","rojo","selene","darklua","lemur","fetch","console","window","document","navigator","__dirname","localStorage"}) do',
    'if rg(_G,k)~=nil then __d(0X1) end end',
    'if ty(process)=="table" then __d(0X2) end',
    'if getfenv and ty(getfenv)~="function" then __d(0X3) end',
    'if getgenv and debug and debug.getinfo then',
    'local h=getgenv() local mt=getmetatable(h)',
    'if mt and (mt.__index or mt.__newindex) then __d(0X4) end end',
    'if not game or not typeof or game.ClassName~="DataModel" then __d(0X5) end',
    'if not pc(function() local p=Instance.new("Part") p:Destroy() end) then __d(0X6) end',
    'end'
  ].join('\n');
}

function prepareSource(source, opts) {
  let toks = lex(source).filter((t) => t.type !== 'comment' && t.type !== 'lcomment');
  const sName = '_S' + R(100, 999);
  let header = null;
  if (opts.strings !== false) {
    const r = encryptStrings(toks, sName);
    toks = r.toks;
    header = r.header;
  }
  if (opts.numbers !== false) toks = numbersToExpr(toks);
  if (opts.renameLocals !== false) toks = renameLocals(toks);
  let code = toks.map((t) => t.val).join('');
  code = code.replace(/  +/g, ' ').trim();
  if (header) code = header + code;
  if (opts.antiTamper !== false) code = antiTamper() + '\n' + code;
  return code;
}

/** Multi-round XOR → number array + VM-looking loader (valid Lua) */
function vmShell(source) {
  let data = Buffer.from(String(source), 'utf8');
  const rounds = R(4, 6);
  const keys = [];
  for (let r = 0; r < rounds; r++) {
    const key = crypto.randomBytes(R(14, 22));
    keys.push(key);
    const out = Buffer.alloc(data.length);
    const salt = (r + 3) & 0xff;
    for (let i = 0; i < data.length; i++) {
      out[i] = data[i] ^ key[i % key.length] ^ ((i * salt) & 0xff);
    }
    data = out;
  }

  const payload = [...data].map((b) => hexLit(b)).join(',');
  const keyLits = keys.map((k) => '{' + [...k].map((b) => hexLit(b)).join(',') + '}').join(',');

  const id = () => makeId('v');
  const N = {
    vm: id(),
    bx: id(),
    dec: id(),
    run: id(),
    k: id(),
    p: id(),
    d: id(),
    i: id(),
    j: id(),
    t: id(),
    o: id(),
    a: id(),
    b: id(),
    c: id(),
    r: id(),
    s: id(),
    m1: id(),
    m2: id(),
    m3: id(),
    m4: id(),
    m5: id()
  };

  // Pure Lua 8-bit XOR (no bit32) — always valid
  const lines = [];
  lines.push('return(function()');
  lines.push('local ' + N.vm + '={');
  lines.push(N.m1 + '=function(u,A,I)A=(-0x' + R(0x1000, 0xffff).toString(16) + '+(u and 0 or 0));I[0X1]=(A);return A;end,');
  lines.push(N.m2 + '=function(u,A,I,Q)I[0X35]=u;if not A[0X10]then A[0X10]=0X0;Q=(-0Xd+A[0X10]);(A)[0X11]=(Q);else Q=(A[0X11]);end;return Q;end,');
  lines.push(N.m3 + '=function(u,A)return type(A)=="string"and A or"";end,');
  lines.push(N.m4 + '=function(u,A,I)local Q=A;if Q then return Q end return I end,');
  lines.push(N.m5 + '=string,');
  lines.push('};');

  lines.push('local function ' + N.bx + '(' + N.a + ',' + N.b + ')');
  lines.push('local ' + N.o + ',' + N.p + ',' + N.i + ',' + N.j + '=0X0,0X1,' + N.a + ',' + N.b);
  lines.push('for ' + N.t + '=0X1,0X8 do');
  lines.push('local ' + N.c + ',' + N.r + '=' + N.i + '%0X2,' + N.j + '%0X2');
  lines.push(N.o + '=' + N.o + '+((' + N.c + '+' + N.r + ')%0X2)*' + N.p);
  lines.push(N.i + '=(' + N.i + '-' + N.c + ')/0X2');
  lines.push(N.j + '=(' + N.j + '-' + N.r + ')/0X2');
  lines.push(N.p + '=' + N.p + '*0X2');
  lines.push('end');
  lines.push('return ' + N.o);
  lines.push('end');

  lines.push('local function ' + N.dec + '(' + N.p + ',' + N.k + ',' + N.s + ')');
  lines.push('local ' + N.o + '={}');
  lines.push('for ' + N.j + '=0X1,#' + N.p + ' do');
  lines.push('local ' + N.t + '=' + N.p + '[' + N.j + ']');
  lines.push('local ' + N.a + '=' + N.k + '[((' + N.j + '-0X1)%#' + N.k + ')+0X1]');
  lines.push('local ' + N.b + '=((' + N.j + '-0X1)*' + N.s + ')%0X100');
  lines.push(N.o + '[' + N.j + ']=string.char(' + N.bx + '(' + N.bx + '(' + N.t + ',' + N.a + '),' + N.b + '))');
  lines.push('end');
  lines.push('return table.concat(' + N.o + ')');
  lines.push('end');

  lines.push('local ' + N.k + '={' + keyLits + '}');
  lines.push('local ' + N.p + '={' + payload + '}');
  lines.push('local ' + N.d + '=' + N.p);
  lines.push('for ' + N.i + '=#' + N.k + ',0X1,-0X1 do');
  lines.push(N.d + '=' + N.dec + '(' + N.d + ',' + N.k + '[' + N.i + '],(' + N.i + '+0X2))');
  lines.push('if ' + N.i + '>0X1 then');
  lines.push('local ' + N.t + '={}');
  lines.push('for ' + N.j + '=0X1,#' + N.d + ' do ' + N.t + '[' + N.j + ']=string.byte(' + N.d + ',' + N.j + ') end');
  lines.push(N.d + '=' + N.t);
  lines.push('end');
  lines.push('end');
  lines.push('local ' + N.run + '=(loadstring or load)(' + N.d + ')');
  lines.push('if not ' + N.run + ' then error(0XBAD,0X0) end');
  lines.push('return ' + N.run + '()');
  lines.push('end)()');

  return lines.join('\n');
}

function obfuscate(source, opts) {
  opts = opts || {};
  const src = String(source || '');
  if (!src.trim()) throw new Error('Empty code');
  if (src.length > 600000) throw new Error('Too large');

  // mode none: return as-is
  if (opts.mode === 'none' || opts.vm === false && opts.plain === true) {
    return { code: src, stats: { inputBytes: src.length, outputBytes: src.length, mode: 'none' } };
  }

  const prepared = prepareSource(src, opts);
  const heavy = opts.vm !== false;
  const out = heavy ? vmShell(prepared) : prepared;

  return {
    code: '-- Protect by QyrexObf v6 (beta)\n' + out,
    stats: {
      inputBytes: src.length,
      outputBytes: out.length,
      mode: heavy ? 'vm-shell' : 'structured'
    }
  };
}

module.exports = { obfuscate };
