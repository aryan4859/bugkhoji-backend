import { UAParser } from 'ua-parser-js';
import axios from 'axios';

export function parseUserAgent(ua: string) {
  const result = UAParser(ua);
  
  return {
    browser: `${result.browser.name || 'Unknown'} ${result.browser.version || ''}`.trim(),
    os: `${result.os.name || 'Unknown'} ${result.os.version || ''}`.trim(),
    device: result.device.type || 'desktop'
  };
}

export async function getGeoLocation(ip: string): Promise<string> {
  try {
    if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.')) {
      return 'Local Network';
    }
    
    const res = await axios.get(`https://ipapi.co/${ip}/json/`);
    return `${res.data.city}, ${res.data.country_name}`;
  } catch (error) {
    console.error('Geolocation error:', error);
    return 'Unknown Location';
  }
}