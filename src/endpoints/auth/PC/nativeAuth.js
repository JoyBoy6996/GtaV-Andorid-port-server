/**
 * Native .asmx auth endpoints used by the Android GTA port client.
 *
 * SOURCE_CONFIRMED from libgtav.so (com.thegwchr.fuzzy):
 *  - rlRosCreateTicketScAuthTokenTask -> auth.asmx/CreateTicketScAuthToken
 *  - rlScGetScAuthTokenTask           -> socialclub.asmx/GetScAuthToken
 *  - rlScCreateScAuthTokenTask        -> socialclub.asmx/CreateScAuthToken
 *
 * The launcher (LauncherActivity.requestGameLaunch) mints a 43-char launch
 * ticket via POST /gwsc/api/game-launch and passes it to the native game as
 * `gwscLaunchToken`. The native game posts it back as `launchToken` on
 * CreateTicketSc3 (and as `scAuthToken` / `ticket` on the other .asmx auth
 * calls) in the RC4-encrypted form body to exchange it for credentials.
 *
 * The native parser (rlRosXmlCreateTicketResponseParser) reads the privilege
 * bitmask from the `Privileges` ATTRIBUTE on <PlayerAccountId>. Privilege 7 is
 * the client's banned flag: CNetwork::CheckNetworkAccess -> HasRosPrivilege(7)
 * returns ACCESS_DENIED_BANNED -> SC_ERROR_BANNED ("permanent ban") popup.
 * Never grant 7; grant 3 (multiplayer) and 5 (standard access).
 */
import xml from 'xml';
import { prisma } from '../../../main.js';
import { getGwscSessionByTicket } from '../../../services/gwscSessionService.js';

const GRANTED_PRIVILEGES = [0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19, 21, 22];

function responseXml(children) {
  return xml(
    {
      Response: [
        { _attr: { 'xmlns:xsd': 'http://www.w3.org/2001/XMLSchema', 'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance' } },
        ...children,
      ],
    },
    { declaration: true }
  );
}

function createTicketXml(user, { ticket, sessionTicket, sessionId }) {
  const privileges = GRANTED_PRIVILEGES.join(',');
  // Keep native service hosts aligned with the deployed private server;
  // never fall back to an official Rockstar host.
  const host = process.env.ROS_HOST || process.env.DOMAIN || 'gta-joyboy.myddns.me';
  const services = [
    { ep: '*/Accounts.svc/*', h: host },
    { ep: '*/Feed.asmx/*', h: host },
    { ep: '*/Telemetry.asmx/*', h: host },
    { ep: '*/ProfileStats.asmx/*', h: host },
    { ep: '*/matchmaking.asmx/*', h: host },
    { ep: '*/Presence.asmx/*', h: host },
    { ep: '*/Inbox.asmx/*', h: host },
    { ep: '*/Clans.asmx/*', h: host },
    { ep: '*/socialclub.asmx/*', h: host },
  ];
  // SOURCE_CONFIRMED: rlRosXmlCreateTicketResponseParser::Parse first finds
  // <Result>, then reads the credential fields inside it. All fields placed
  // directly under <Response> are ignored.
  return responseXml([
    { Status: '1' },
    {
      Result: [
        { Ticket: ticket },
        { PosixTime: String(Math.floor(Date.now() / 1000)) },
        { SecsUntilExpiration: '86399' },
        { Region: '1' },
        // Privileges must be an ATTRIBUTE on PlayerAccountId, and the Rockstar
        // id must be TEXT inside that element. `xml` ignores `_content`; using
        // an array makes it emit both the attribute and the numeric text that
        // rlRosXmlCreateTicketResponseParser::Parse feeds to sscanf("%lld").
        { PlayerAccountId: [{ _attr: { Privileges: privileges } }, String(user.RockstarId)] },
        { DisabledSecurityFlags: '0' },
        { SessionId: String(sessionId) },
        { SessionKey: user.SessionKey || '' },
        { SessionTicket: sessionTicket },
        { CloudKey: '' },
        { PublicIp: '' },
        { IsSubAccount: 'false' },
        {
          Services: [
            { _attr: { Count: String(services.length) } },
            {
              Hosts: services.map((s) => ({ S: { _attr: { ep: s.ep, h: s.h } } })),
            },
          ],
        },
        {
          RockstarAccount: [
            { RockstarId: String(user.RockstarId) },
            { Age: '25' },
            { AvatarUrl: '' },
            { CountryCode: 'US' },
            { Email: user.email || '' },
            { LanguageCode: 'en' },
            { Nickname: user.PCNickname || user.name || `User${user.RockstarId}` },
          ],
        },
      ],
    },
  ]);
}

function scAuthTokenXml(token) {
  // SOURCE_CONFIRMED: rlScCreateScAuthTokenTask::ProcessSuccess reads the text
  // content of <Result> into its token buffer. Repeat the token on the root as
  // ScAuthToken to keep the wider ROS shape.
  return xml(
    {
      Response: [
        {
          _attr: {
            ScAuthToken: token,
            'xmlns:xsd': 'http://www.w3.org/2001/XMLSchema',
            'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
          },
        },
        { Status: '1' },
        { Result: token },
      ],
    },
    { declaration: true }
  );
}

function errorXml(status, message) {
  return responseXml([{ Status: String(status) }, { Message: message }]);
}

function findTicketValue(req) {
  const body = req.body || {};
  return (
    body.scAuthToken ||
    body.authToken ||
    body.token ||
    body.ticket ||
    body.launchToken ||
    req.query?.scAuthToken ||
    req.query?.token ||
    req.headers['x-gwsc-token'] ||
    req.headers['ros-sessionticket'] ||
    ''
  );
}

async function resolveUser(req) {
  // 1) Gwsc launch ticket (43-char, in-memory session)
  const token = findTicketValue(req);
  const session = getGwscSessionByTicket(token);
  if (session?.userId) {
    return prisma.user.findFirst({ where: { id: session.userId } });
  }
  if (session?.email) {
    return prisma.user.findFirst({ where: { email: session.email } });
  }

  // 2) DB-backed native credentials (Ticket / SessionTicket / SCAuthToken)
  if (token) {
    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { Ticket: token },
          { SessionTicket: token },
          { SCAuthToken: token },
        ],
      },
    });
    if (user) return user;
  }

  // 3) Ros-SessionTicket header
  const header = req.headers['ros-sessionticket'] || req.headers['ros-session-ticket'];
  if (header) {
    return prisma.user.findFirst({
      where: { OR: [{ SessionTicket: header }, { Ticket: header }] },
    });
  }
  return null;
}

/** auth.asmx/CreateTicketScAuthToken + socialclub.asmx/CreateTicketScAuthToken
 *  and generic CreateTicket variants: exchange the launch ticket for a full
 *  native credential XML with a parser-valid privilege attribute. */
export const nativeCreateTicketHandler = async (req, res) => {
  res.set('Content-Type', 'text/xml');
  try {
    const user = await resolveUser(req);
    if (!user || user.banned) {
      return res.send(errorXml(401, 'A valid account token is required'));
    }
    const ticket = user.Ticket || findTicketValue(req);
    const sessionTicket = user.SessionTicket || ticket;
    const sessionId = Number(user.SessionId) || Math.floor(Date.now() / 1000);
    return res.send(createTicketXml(user, { ticket, sessionTicket, sessionId }));
  } catch (e) {
    console.error('nativeCreateTicket error:', e);
    return res.send(errorXml(500, 'Internal error'));
  }
};

/** socialclub.asmx/GetScAuthToken + CreateScAuthToken */
export const nativeScAuthTokenHandler = async (req, res) => {
  res.set('Content-Type', 'text/xml');
  try {
    const user = await resolveUser(req);
    if (!user || user.banned) {
      return res.send(errorXml(401, 'A valid account token is required'));
    }
    const token = user.SCAuthToken || findTicketValue(req);
    return res.send(scAuthTokenXml(token));
  } catch (e) {
    console.error('nativeScAuthToken error:', e);
    return res.send(errorXml(500, 'Internal error'));
  }
};
