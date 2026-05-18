const TRUSTED_DOMAINS = new Set([
  'google.com', 'youtube.com', 'gmail.com', 'drive.google.com', 'docs.google.com',
  'accounts.google.com', 'mail.google.com', 'plus.google.com', 'groups.google.com',
  'maps.google.com', 'play.google.com', 'support.google.com', 'developers.google.com',
  'github.com', 'github.io', 'raw.githubusercontent.com',
  'microsoft.com', 'live.com', 'office.com', 'office365.com', 'outlook.com',
  'login.microsoftonline.com', 'login.live.com', 'account.microsoft.com',
  'azure.com', 'azureedge.net', 'visualstudio.com',
  'apple.com', 'icloud.com', 'appleid.apple.com',
  'facebook.com', 'fb.com', 'messenger.com', 'instagram.com',
  'twitter.com', 'x.com', 't.co',
  'linkedin.com', 'linkedin.cn',
  'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.co.jp',
  'aws.amazon.com', 'amazonaws.com',
  'discord.com', 'discordapp.com', 'discord.gg', 'discord.media',
  'steamcommunity.com', 'steampowered.com', 'steamstore.com',
  'twitch.tv', 'twitchcdn.net',
  'paypal.com', 'paypal.me', 'paypalobjects.com',
  'ebay.com', 'ebay.co.uk', 'ebay.de',
  'netflix.com', 'nflxvideo.net', 'nflximg.net',
  'spotify.com', 'spotifycdn.net',
  'adobe.com', 'adobe.io', 'adobedc.net',
  'dropbox.com', 'dropboxapi.com', 'dropboxstatic.com',
  'telegram.org', 't.me',
  'whatsapp.com', 'whatsapp.net',
  'cloudflare.com', 'cloudflare.net', 'cloudflareinsights.com',
  'wordpress.com', 'wp.com',
  'blogger.com', 'blogspot.com',
  'wikipedia.org', 'wikimedia.org',
  'stackoverflow.com', 'stackexchange.com',
  'npmjs.com', 'npmjs.org',
  'docker.com', 'docker.io',
  'slack.com', 'slack-edge.com',
  'reddit.com', 'redditmedia.com', 'redditstatic.com',
  'medium.com', 'medium.fi',
  'notion.so', 'notion.site',
  'figma.com', 'figma.io',
  'gitlab.com', 'gitlab.io',
  'bitbucket.org', 'bitbucket.io',
  'atlassian.com', 'atlassian.net',
  'trello.com', 'trello.net',
  'jira.com', 'atlassian.com',
  'zoom.us', 'zoom.com',
  'teamviewer.com', 'teamviewer.cn',
  'vercel.com', 'vercel.app',
  'netlify.com', 'netlify.app',
  'herokuapp.com', 'heroku.com',
  'repl.it', 'replit.com',
  'codepen.io', 'codesandbox.io',
  'jsfiddle.net', 'jsbin.com',
  'googleapis.com', 'gstatic.com', 'googleusercontent.com',
  'youtube-nocookie.com', 'ytimg.com',
  'vimeo.com', 'vimeocdn.com',
  'dailymotion.com', 'dailymotioncdn.com',
  'soundcloud.com', 'sndcdn.com',
  'bandcamp.com', 'bandcampcdn.com',
  'patreon.com', 'patreonusercontent.com',
  'kickstarter.com', 'ksr-ugc.imgix.net',
  'indiegogo.com', 'iggcdn.com',
  'googletagmanager.com', 'google-analytics.com',
  'facebook.net', 'fbcdn.net',
  'twitter.com', 'twimg.com',
  'linkedin.com', 'licdn.com',
  'cloudfront.net', 'amazonaws.com',
  'fastly.net', 'fastly.com',
  'jsdelivr.net', 'cdnjs.com',
  'unpkg.com', 'cdn.jsdelivr.net',
  'googleadservices.com', 'doubleclick.net',
  'brave.com', 'braveusercontent.com',
  'mozilla.org', 'firefox.com', 'thunderbird.net',
  'duckduckgo.com', 'duck.com',
  'proton.me', 'protonmail.com', 'protonvpn.com',
])

const HIGH_VALUE_TARGETS = [
  'google', 'gmail', 'youtube',
  'facebook', 'instagram', 'twitter', 'linkedin',
  'github', 'gitlab', 'bitbucket',
  'microsoft', 'outlook', 'office', 'windows', 'azure',
  'apple', 'icloud', 'itunes',
  'amazon', 'aws', 'prime',
  'paypal', 'ebay',
  'netflix', 'spotify', 'twitch',
  'discord', 'steam', 'epicgames',
  'reddit', 'medium', 'notion',
  'dropbox', 'adobe', 'zoom',
  'whatsapp', 'telegram', 'signal',
  'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'hsbc',
  'capitalone', 'amex', 'discover',
]

const TRUSTED_HOSTING_PREFIXES = [
  'github.io', 'pages.dev', 'vercel.app', 'netlify.app',
  'herokuapp.com', 'onrender.com', 'fly.dev',
  'firebaseapp.com', 'web.app', 'appspot.com',
  'azurewebsites.net', 'awsapps.com',
  'repl.co', 'gitlab.io', 'bitbucket.io',
]

function isTrustedDomain(domain) {
  if (!domain) return false
  const d = domain.toLowerCase()
  if (TRUSTED_DOMAINS.has(d)) return true
  for (const prefix of TRUSTED_HOSTING_PREFIXES) {
    if (d.endsWith('.' + prefix) || d === prefix) return true
  }
  return false
}

function getTrustedWeight(domain) {
  if (!domain) return 1.0
  return isTrustedDomain(domain) ? 0.5 : 1.0
}

function isHighValueTarget(domain) {
  if (!domain) return false
  const d = domain.toLowerCase()
  const parts = d.split('.')
  const root = parts.length > 2 ? parts[parts.length - 2] : parts[0]
  return HIGH_VALUE_TARGETS.includes(root)
}
