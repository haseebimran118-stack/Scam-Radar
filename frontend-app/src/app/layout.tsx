import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Scam Radar | Threat Intelligence",
  description:
    "Malicious URL detection and threat intelligence dashboard",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}