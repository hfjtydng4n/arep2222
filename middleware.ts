import { NextRequest, NextResponse } from 'next/server';

const ALLOW = new Set([
  '/robots.txt',
  '/favicon.ico',
  '/sitemap.xml',
  '/api/health',
]);

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // allow Next.js internals and public files without auth
  if (
    pathname.startsWith('/_next/') ||
    pathname.startsWith('/static/') ||
    pathname.startsWith('/images/') ||
    ALLOW.has(pathname)
  ) {
    const res = NextResponse.next();
    res.headers.set('X-Robots-Tag', 'noindex, nofollow, noarchive');
    return res;
  }

  const user = process.env.BASIC_AUTH_USER || '';
  const pass = process.env.BASIC_AUTH_PASS || '';

  // if env missing, fail closed (block)
  if (!user || !pass) {
    return new NextResponse('Auth misconfigured (missing env vars)', {
      status: 401,
      headers: {
        'WWW-Authenticate': 'Basic realm="Staging"',
        'X-Robots-Tag': 'noindex, nofollow, noarchive',
        'Cache-Control': 'no-store',
      },
    });
  }

  // check Authorization header
  const header = req.headers.get('authorization') || '';
  const [scheme, encoded] = header.split(' ');
  if (scheme !== 'Basic' || !encoded) {
    return new NextResponse('Authentication required', {
      status: 401,
      headers: {
        'WWW-Authenticate': 'Basic realm="Staging"',
        'X-Robots-Tag': 'noindex, nofollow, noarchive',
        'Cache-Control': 'no-store',
      },
    });
  }

  try {
    const decoded = Buffer.from(encoded, 'base64').toString();
    const [u, p] = decoded.split(':');
    if (u === user && p === pass) {
      const res = NextResponse.next();
      res.headers.set('X-Robots-Tag', 'noindex, nofollow, noarchive');
      return res;
    }
  } catch {
    // fall through to unauthorized
  }

  return new NextResponse('Unauthorized', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="Staging"',
      'X-Robots-Tag': 'noindex, nofollow, noarchive',
      'Cache-Control': 'no-store',
    },
  });
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml|images/).*)',
  ],
};
