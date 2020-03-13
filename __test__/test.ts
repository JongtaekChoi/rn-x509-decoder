import X509DERSpec from '../x509';
import base64string from './encodedBase64';

describe('Parsing base64string', () => {
  it('can parse base64string', () => {
    const parsed = new X509DERSpec(base64string)
    expect(parsed.toString()).toMatchSnapshot();
  })
});