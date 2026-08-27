// A minimal XML tree model shared by the NBFX encoder (build request bytes from
// an XML string) and decoder (render decoded records back to XML / walk them).
// Not a general XML processor — just enough for the SOAP envelopes ADWS uses.

// Node shapes:
//   element: { kind:'el', prefix, name, attrs:[Attr], children:[Node] }
//   text:    { kind:'text', value }
//   Attr:    { xmlns:bool, prefix, name, value }

export function el(prefix, name, attrs = [], children = []) {
  return { kind: 'el', prefix, name, attrs, children };
}
export function text(value) { return { kind: 'text', value }; }

const NAME = /[^\s/>=]+/y;

// Parse an XML string into a forest (array of root nodes). Whitespace-only text
// between elements is dropped so it does not become spurious NBFX text records.
export function parseXml(src) {
  let i = 0;
  const roots = [];
  const stack = [{ children: roots }];
  const top = () => stack[stack.length - 1];

  while (i < src.length) {
    if (src[i] === '<') {
      if (src.startsWith('<?', i)) { i = src.indexOf('?>', i) + 2; continue; }
      if (src.startsWith('<!--', i)) { i = src.indexOf('-->', i) + 3; continue; }
      if (src[i + 1] === '/') {                       // end tag
        const close = src.indexOf('>', i);
        stack.pop();
        i = close + 1;
        continue;
      }
      // start tag
      i++;
      NAME.lastIndex = i;
      const m = NAME.exec(src);
      const qname = m[0];
      i = NAME.lastIndex;
      const [prefix, name] = splitQ(qname);
      const node = el(prefix, name);
      // attributes
      for (;;) {
        while (i < src.length && /\s/.test(src[i])) i++;
        if (src[i] === '>' || src[i] === '/') break;
        NAME.lastIndex = i;
        const am = NAME.exec(src);
        const aq = am[0];
        i = NAME.lastIndex;
        while (i < src.length && /\s/.test(src[i])) i++;
        let value = '';
        if (src[i] === '=') {
          i++;
          while (/\s/.test(src[i])) i++;
          const quote = src[i++];
          const end = src.indexOf(quote, i);
          value = unescapeXml(src.slice(i, end));
          i = end + 1;
        }
        if (aq === 'xmlns') node.attrs.push({ xmlns: true, prefix: '', name: '', value });
        else if (aq.startsWith('xmlns:')) node.attrs.push({ xmlns: true, prefix: aq.slice(6), name: '', value });
        else { const [ap, an] = splitQ(aq); node.attrs.push({ xmlns: false, prefix: ap, name: an, value }); }
      }
      top().children.push(node);
      if (src[i] === '/') { i = src.indexOf('>', i) + 1; }   // self-closing
      else { stack.push(node); i++; }
    } else {
      const next = src.indexOf('<', i);
      const chunk = src.slice(i, next === -1 ? src.length : next);
      if (chunk.trim()) top().children.push(text(unescapeXml(chunk)));
      i = next === -1 ? src.length : next;
    }
  }
  return roots;
}

function splitQ(q) {
  const c = q.indexOf(':');
  return c === -1 ? ['', q] : [q.slice(0, c), q.slice(c + 1)];
}

export function escapeXml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
export function unescapeXml(s) {
  return String(s).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'").replace(/&amp;/g, '&');
}

// Serialize a forest back to an XML string (used for logging / debugging).
export function serializeXml(nodes) {
  let out = '';
  for (const n of nodes) {
    if (n.kind === 'text') { out += escapeXml(n.value); continue; }
    const tag = n.prefix ? `${n.prefix}:${n.name}` : n.name;
    let attrs = '';
    for (const a of n.attrs) {
      if (a.xmlns) attrs += a.prefix ? ` xmlns:${a.prefix}="${escapeXml(a.value)}"` : ` xmlns="${escapeXml(a.value)}"`;
      else attrs += ` ${a.prefix ? a.prefix + ':' : ''}${a.name}="${escapeXml(a.value)}"`;
    }
    if (!n.children.length) { out += `<${tag}${attrs}/>`; continue; }
    out += `<${tag}${attrs}>${serializeXml(n.children)}</${tag}>`;
  }
  return out;
}
