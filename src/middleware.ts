import { NextRequest, NextResponse } from 'next/server';

export function middleware(req: NextRequest) {
  const url = req.nextUrl;

  // Allow framework assets and public files without auth
  if (
    url.pathname.startsWith('/_next') ||
    url.pathname.startsWith('/api') ||
    url.pathname === '/robots.txt' ||
    url.pathname.startsWith('/favicon')
  ) {
    return NextResponse.next();
  }

  const user = process.env.BASIC_AUTH_USER;
  const pass = process.env.BASIC_AUTH_PASS;

  // If env vars are missing, do not block (useful for local dev if you forget)
  if (!user || !pass) return NextResponse.next();

  const header = req.headers.get('authorization') || '';
  const [scheme, encoded] = header.split(' ');
  if (scheme !== 'Basic' || !encoded) {
    return new NextResponse('Auth required.', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="Protected"' },
    });
  }

  const decoded = Buffer.from(encoded, 'base64').toString();
  const [u, p] = decoded.split(':');

  if (u === user && p === pass) return NextResponse.next();

  return new NextResponse('Unauthorized', {
    status: 401,
    headers: { 'WWW-Authenticate': 'Basic realm="Protected"' },
  });
}

export const config = {
  matcher: ['/((?!_next|api|robots.txt|favicon.ico).*)'],
};
