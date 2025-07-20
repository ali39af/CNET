# 🌐 CNET – Clean & Safe Internet for Everyone

**CNET** is your all-in-one browser protection tool, designed to create a cleaner, safer, and distraction-free internet experience for users of all ages.

> ⚠️ **Note**: This is an early version. Features are currently implemented at a basic level. There's no database or advanced backend structure yet — just basic functionality for testing purposes. Please don’t judge it too harshly; it’s just the beginning!

---

## 🚀 Features

- **🛑 Block Ads**  
  Eliminate intrusive ads and enjoy a faster, clutter-free browsing experience.

- **🔒 Block Scam Websites**  
  Stay protected from phishing, malware, and fraudulent websites with real-time detection and blocking.

- **🚫 Block NSFW Content**  
  Automatically filter out inappropriate or explicit content for a safer online environment.

- **🧩 Flexible Control**  
  You can disable NSFW and scam protection features at any time through a toggle button on the blocked webpage.

- **🌍 Proxy Support (Experimental)**  
  Bypass regional restrictions and access websites that block users from your region (e.g. `docker.com` blocks Iranian users) using built-in proxy functionality.  
  - **Supported protocols:** HTTP, HTTPS (TLS 1.3 only)  
  - **Coming soon:** QUIC (HTTP/3) support for faster and more secure connections  
  - Includes a **Captive Portal**. You must access the proxy through the specified Captive Portal IP address for it to function properly.

---

## ✅ Why Use CNET?

- Simple setup — no technical knowledge required  
- Lightweight and efficient — won’t slow down your browser  
- Regular updates to stay ahead of new threats  
- Family-friendly by default

---

## 📋 TODO (Upcoming Features)

| Feature                                   | Status       | Description                                                                 |
|------------------------------------------|--------------|-----------------------------------------------------------------------------|
| Database Integration                     | ✔️ Finished   | Store user data, configurations, logs. we plan to use EF Core              |
| QUIC / HTTP/3 Protocol Support           | ❌ Not yet    | Enable faster and modern proxy connectivity                                |
| User Bandwidth | Speed Control           | ❌ Not yet    | Manage and limit traffic per user                                          |
| Proxy Management Dashboard               | ✔️ Finished   | Admin panel to manage and monitor proxy traffic/users                      |
| Subscription System for Providers        | ❌ Not yet    | Allow providers to offer paid proxy access                                 |
| Load Balancing for Proxy Infrastructure  | ❌ Not yet    | Horizontal scaling to support high number of users efficiently             |
| IPV6 Support                             | ❌ Not yet    | can connect to DNS, Router via IPV6 currently we have a little IPV6 Config |

---

## 📣 Contributing

We welcome contributions!  
Whether it’s a bug fix, feature request, or an idea for improvement — feel free to open an issue or submit a pull request.

---

## 📜 License

MIT License
