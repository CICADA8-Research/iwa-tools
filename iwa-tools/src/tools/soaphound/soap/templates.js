// WS-Enumeration SOAP envelopes for ADWS. Compact (no inter-element whitespace)
// so the NBFX encoder emits no stray text records. Mirrors the templates in
// SoaPy src/soap_templates.py.

import { escapeXml } from '../encoder/xml.js';

const NS =
  'xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
  'xmlns:a="http://www.w3.org/2005/08/addressing" ' +
  'xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" ' +
  'xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" ' +
  'xmlns:xsd="http://www.w3.org/2001/XMLSchema" ' +
  'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"';

function header(action, fqdn, port, endpoint, uuid) {
  return `<s:Header>` +
    `<a:Action s:mustUnderstand="1">${action}</a:Action>` +
    `<ad:instance>ldap:389</ad:instance>` +
    `<a:MessageID>urn:uuid:${uuid}</a:MessageID>` +
    `<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>` +
    `<a:To s:mustUnderstand="1">net.tcp://${fqdn}:${port}/ActiveDirectoryWebServices/Windows/${endpoint}</a:To>` +
    `</s:Header>`;
}

export function enumerateXml({ fqdn, port, uuid, query, baseObject, attributes, rangeHints }) {
  const sel = (attributes || [])
    .map((a) => {
      const r = rangeHints && rangeHints[a];
      let range = '';
      if (r) {
        range = ` RangeLow="${r.low}"`;
        if (r.high !== undefined && r.high !== null) range += ` RangeHigh="${r.high}"`;
      }
      return `<ad:SelectionProperty${range}>addata:${a}</ad:SelectionProperty>`;
    }).join('');
  return `<s:Envelope ${NS}>` +
    header('http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate', fqdn, port, 'Enumeration', uuid) +
    `<s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:adlq="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery">` +
    `<wsen:Enumerate>` +
    `<wsen:Filter Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery">` +
    `<adlq:LdapQuery>` +
    `<adlq:Filter>${escapeXml(query)}</adlq:Filter>` +
    `<adlq:BaseObject>${escapeXml(baseObject)}</adlq:BaseObject>` +
    `<adlq:Scope>Subtree</adlq:Scope>` +
    `</adlq:LdapQuery></wsen:Filter>` +
    `<ad:Selection Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1">${sel}</ad:Selection>` +
    `</wsen:Enumerate></s:Body></s:Envelope>`;
}

export function pullXml({ fqdn, port, uuid, enumCtx, maxElements = 256 }) {
  return `<s:Envelope ${NS}>` +
    header('http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull', fqdn, port, 'Enumeration', uuid) +
    `<s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">` +
    `<wsen:Pull>` +
    `<wsen:EnumerationContext>${escapeXml(enumCtx)}</wsen:EnumerationContext>` +
    `<wsen:MaxElements>${maxElements}</wsen:MaxElements>` +
    `<ad:controls><ad:control type="1.2.840.113556.1.4.801" criticality="true">` +
    `<ad:controlValue xsi:type="xsd:base64Binary">MIQAAAADAgEH</ad:controlValue></ad:control></ad:controls>` +
    `</wsen:Pull></s:Body></s:Envelope>`;
}

// "pk.lab" -> "DC=pk,DC=lab"
export function domainToBaseDN(domain) {
  return domain.split('.').map((p) => `DC=${p}`).join(',');
}
