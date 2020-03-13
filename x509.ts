import { Buffer } from 'buffer';
import utf8 from 'utf-8';

export enum IdentifierClass {
  Universal,
  Application,
  'Context-specific',
  Private,
}
export enum IdentifierPC {
  Primitive,
  Constructed
}

export enum TAG {
  EOC,
  BOOLEAN,
  INTEGER,
  BIT_STRING,
  OCTET_STRING,
  NULL,
  OID,
  Object_Descriptor,
  EXTERNAL,
  REAL,
  ENUMERATED,
  EMBEDDED_PDV,
  UTF8String,
  RELATIVE_OID,
  TIME,
  Reserved,
  SEQUENCE,
  SET,
  NumericString,
  PrintableString,
  T61String,
  VideotexSt,
  IA5String,
  UTCTime,
  GeneralizedTime,
  GraphicString,
  VisibleString,
  GeneralString,
  UniversalString,
  CHARACTER_STRING,
  BMPString,
  DATE,
  TIME_OF_DAY,
  DATE_TIME,
  DURATION,
  OID_IRI,
  RELATIVE_OID_IRI
}

export interface Identifier {
  class: IdentifierClass,
  pc: IdentifierPC,
  tag: number,
  octets: number,
}

export interface ContentLength {
  indefinite?: boolean
  length?: number,
  octets: number,
}

export class TLV {
  buffer: Buffer;
  identifier: Identifier;
  contentLength?: ContentLength;
  content?: string | boolean | TLV[];

  constructor({ buffer, identifier, content, contentLength }: TLV) {
    this.buffer = buffer;
    this.identifier = identifier;
    this.content = content;
    this.contentLength = contentLength;
  }

  toString(depth: number = 0, includeTag: boolean = true) {
    let indent = ' ';
    for (let i = 0; i < depth; i += 1) {
      indent += ' ';
    }
    const content = this.content != undefined
      ? Array.isArray(this.content)
        ? '\n' + indent + this.content.map(d => d.toString(depth + 1)).reduce((p, n) => p + '\n' + indent + n)
        : this.content
      : null;
    const tag = includeTag ? TAG[this.identifier.tag] + ': ' : ''
    return `${tag}: ${content}`;
  }
}

export class Certificate extends TLV {
  constructor(tlv: TLV) {
    super(tlv);
    console.log(this.content)
  }

  get version() {
    return this.content[0];
  }
  get serialNumber() {
    return this.content[1];
  }
  get signature() {
    return this.content ? this.content[2] : null;
  }
  get issuer() {
    return this.content ? this.content[3] : null;
  }
  get validity() {
    return this.content ? this.content[4] : null;
  }
  get subject() {
    return this.content ? this.content[5] : null;
  }
  get subjectPulicKeyInfo() {
    return this.content ? this.content[6] : null;
  }
  get issuerUID() {
    return this.content ? this.content[7] : null;
  }
  get subjectUID() {
    return this.content ? this.content[8] : null;
  }
  get extensions() {
    return this.content ? this.content[9] : null;
  }

  toString(depth: number = 0) {
    let indent = '';
    for (let i = 0; i < depth; i += 1) {
      indent += ' ';
    }
    return `
${indent}Version${this.version?.toString(depth + 1, false)}
${indent}Serial Number${this.serialNumber?.toString(depth + 1, false)}
${indent}Signature${this.signature?.toString(depth + 1, false)}
${indent}Issuer${this.issuer?.toString(depth + 1, false)}
${indent}Validity${this.validity?.toString(depth + 1, false)}
${indent}Subject${this.subject?.toString(depth + 1, false)}
${indent}Subject Public Key Info${this.subjectPulicKeyInfo?.toString(depth + 1, false)}
${indent}Issuer Unique Identifier${this.issuerUID?.toString(depth + 1, false)}
${indent}Subject Unique Identifier${this.subjectUID?.toString(depth + 1, false)}
${indent}Extensions${this.extensions?.toString(depth + 1, false)}
`
  }
}

export default class X509DERSpec extends TLV {
  certificate: Certificate;
  get signatureAlgorithm(): TLV {
    return this.content ? this.content[1] : null;
  }
  get signature(): TLV {
    return this.content ? this.content[2] : null;
  }

  constructor(der: string) {
    const buffer = new Buffer(der, 'base64');
    const tlvs = decodeTLV(buffer);
    super(tlvs[0])
    this.certificate = new Certificate(this.content[0]);
  }

  toString() {
    return `
Certificate:${this.certificate?.toString(1)}
Certificate Signature Algorithm:${this.signatureAlgorithm?.toString(1, false)}
Certificate Signature:${this.signature?.toString(1, false)}
`
  }
}
function getIdentifier(buffer: Buffer, index: number): Identifier {
  const value = buffer.readUInt8(index);
  const c: IdentifierClass = value >> 6;
  const pc: IdentifierPC = value >> 5 & 1;
  let tag: number = value & 31;
  let octets = 1;
  if (tag === 31) {
    octets = 2;
    tag = buffer.readUInt8(index + 1) & 63;
  }
  const id = {
    class: c,
    pc,
    tag,
    octets
  }
  return id
}

function getContentLength(buffer: Buffer, index: number): ContentLength {
  const value = buffer.readUInt8(index);
  if (value < 128) {
    return {
      length: value,
      octets: 1
    }
  } else {
    const octets = value & 127;
    if (octets === 0) {
      return {
        indefinite: true,
        octets: 1,
      }
    } else {
      let contentLength = 0;
      for (let i = 0; i < octets; i += 1) {
        const n = buffer.readUInt8(index + i + 1);
        contentLength = (contentLength * 256 + n);
      }
      return {
        length: contentLength,
        octets: octets + 1,
      }
    }
  }

}

function toHex(n: number): string {
  const value = (n & 15) + '';
  switch (value) {
    case '15': return 'F';
    case '14': return 'E';
    case '13': return 'D';
    case '12': return 'C';
    case '11': return 'B';
    case '10': return 'A';
    default:
      return value;
  }
}

function buffer2HexString(buffer: Buffer): string {
  let array = "";
  buffer.forEach(b => {
    array += toHex(b >> 4) + toHex(b) + ' ';
  })
  return array.substring(0, array.length - 1);
}

export function decodeTLV(buffer: Buffer, start: number = 0, end: number = buffer.length): TLV[] {
  let i = start;
  const der: TLV[] = [];
  while (i < end) {
    let id = getIdentifier(buffer, i);
    i += id.octets;

    let contentLength: ContentLength = { length: 1, octets: 0 };
    if (id.tag !== 1) {
      contentLength = getContentLength(buffer, i);
    }
    i += contentLength.octets;
    if (i + contentLength.length > buffer.length) {
      throw new Error('last content index cannot bigger than buffer length');
    }
    const contentBuffer = new Buffer(buffer.slice(i, i + contentLength.length))
    let content;
    if (id.pc === IdentifierPC.Constructed) {
      try {
        content = decodeTLV(buffer, i, i + contentLength.length);
      } catch (error) {
        console.error(error);
        content = "ERROR " + error.message;
      }
    } else if ([TAG.IA5String, TAG.PrintableString, TAG.UTCTime].indexOf(id.tag) >= 0) {
      content = contentBuffer.toString();
    } else if (id.tag === TAG.UTF8String) {
      content = utf8.getStringFromBytes(contentBuffer);
    } else if (id.tag === TAG.BOOLEAN) {
      content = !!contentBuffer[0]
    } else {
      content = buffer2HexString(contentBuffer);
    }

    const structure = new TLV({
      buffer: new Buffer(buffer.slice(i, i + contentLength.length)),
      identifier: id,
      contentLength: contentLength,
      content,
    })
    console.log({ content })
    der.push(structure)
    i += contentLength.length;
  }
  // console.log(der);
  return der;
}
