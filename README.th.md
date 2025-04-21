# 🍥Fuwari

แม่แบบสำหรับเว็บบล็อกแบบ static สร้างด้วย [Astro](https://astro.build)

นี้คือ fork ปรับแต่เพื่อให้งานกับ Cloudflare Pages

[**🖥️ ตัวอย่างการใช้งานจริง (Vercel)**](https://fuwari.vercel.app)&nbsp;&nbsp;&nbsp;/&nbsp;&nbsp;&nbsp;
[**📦 เวอร์ชั่นเก่าสำหรับ Hexo**](https://github.com/saicaca/hexo-theme-vivia)

> เวอร์ชั่นของ README: `2024-09-10`

![ภาพตัวอย่าง](https://raw.githubusercontent.com/saicaca/resource/main/fuwari/home.png)

## ✨ คุณสมบัติ

- [x] สร้างด้วย [Astro](https://astro.build) และ [Tailwind CSS](https://tailwindcss.com)
- [x] มีอนิเมชั่นและการเปลี่ยนหน้าอย่างลื่นไหล
- [x] รองรับโหมดสว่าง / โหมดมืด
- [x] ปรับแต่งสีธีมและแบนเนอร์ได้
- [x] Responsive design (หน้าตาเว็บปรับเปลี่ยนตามขนาดจอ)
- [ ] การแสดงความคิดเห็น
- [x] การค้นหา
- [ ] TOC (สารบัญ)

### คุณสมบัติเสริมที่ repository นี้ได้เพิ่ม

- [x] Config สำหรับ Cloudflare Pages
- [x] Cache คำขอ GitHub api ด้วย Cloudflare Workers Cache และ KV

## 🚀 วิธีใช้งาน

1. [Generate repository ใหม่](https://github.com/saicaca/fuwari/generate)ขึ้นมาจากแม่แบบนี้ หรือจะ fork repository นี้ก็ได้
2. เริ่มแก้ไขบล็อกของคุณแบบ local โดยการ clone repository ของคุณ (จากข้อ 1) ไว้ในเครื่องของคุณ แล้วรันคำสั่ง `pnpm install` และ `pnpm add sharp` เพื่อติดตั้ง dependencies ที่จำเป็น
   - ติดตั้ง [pnpm](https://pnpm.io) ด้วยคำสั่ง `npm install -g pnpm` ถ้ายังไม่เคยติดตั้ง
3. แก้ไขไฟล์การตั้งค่า `src/config.ts` เพื่อปรับแต่งบล็อกของคุณ
4. รันคำสั่ง `pnpm new-post <filename>` เพื่อสร้างโพสต์ใหม่ใน `src/content/posts/` และแก้ไขไฟล์โพสต์นั้นๆ ให้สมบูรณ์
5. Deploy เว็บบล็อกของคุณไปยัง cloudflare pages โดยอ้างอิงวิธีการจาก[คู่มือนี้](https://docs.astro.build/en/guides/deploy/cloudflare/#cloudflare-pages) อย่าลืมแก้ไขการตั้งค่าเว็บไซต์ในไฟล์ `astro.config.mjs` และเพิ่ม secret ไปยัง `Variables and Secrets` ในการตั้งค่า cloudflare pages ก่อนที่คุณจะ deploy เว็บ

### ตัวแปรสภาพแวดล้อมที่จำเป็น

- `SECRET_GITHUB_API_CACHE_PAT` - personal access token, เพื่อให้ worker ส่งคำขอไปยัง api.github.com
- `SECRET_GITHUB_API_CACHE_SIG_KEY` - Key `SHA-256` แบบ hex เพื่อใช้เซ็นชื่อ repo เพื่อใช้ตรวจสอบว่า repo นั้นมีใน blog ของคุณจริงๆ

### `astro.config.mjs`

- แก้ไข `kv_namespaces[0].id`, ให้กำหนด `ID` ที่ได้จากการสร้าง KV ใน cloudflare account ของคุณ

## ⚙️ Frontmatter ของโพสต์

```yaml
---
title: โพสต์แรกของฉัน
published: 2023-09-09
description: นี่คือโพสต์แรกของเว็บบล็อก Astro อันใหม่ของฉัน
image: ./cover.jpg
tags: [Foo, Bar]
category: Front-end
draft: false
lang: jp      # เขียนค่านี้เมื่อภาษาของโพสต์นั้นๆ แตกต่างจากภาษาของเว็บไซต์ที่ตั้งค่าไว้ใน `config.ts` เท่านั้น
---
```

## 🧞 คำสั่ง

คำสั่งที่รันได้ใน terminal จาก root ของโปรเจค:

| คำสั่ง                                | ผลที่เกิด                                            |
|:------------------------------------|:--------------------------------------------------|
| `pnpm install` และ `pnpm add sharp` | ติดตั้ง dependencies                                 |
| `pnpm dev`                          | เปิดเซิร์ฟเวอร์เพื่อพัฒนาเว็บแบบ local ที่ `localhost:4321` |
| `pnpm build`                        | Build เว็บไซต์แบบพร้อมใช้งานจริงไปยังโฟลเดอร์ `./dist/`  |
| `pnpm preview`                      | ดูตัวอย่าง build ของคุณแบบ local ก่อนที่จะ deploy จริง    |
| `pnpm new-post <filename>`          | สร้างโพสต์ใหม่                                       |
| `pnpm astro ...`                    | รันคำสั่ง CLI เช่น `astro add`, `astro check`         |
| `pnpm astro --help`                 | ดูข้อมูลเพิ่มเติมเกี่ยวกับ Astro CLI                       |
