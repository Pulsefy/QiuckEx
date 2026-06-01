/**
 * Layout for /pay. The client-side page and page-metadata are handled at the page level.
 */

interface PayLayoutProps {
  children: React.ReactNode;
}

export default function PayLayout({ children }: PayLayoutProps) {
  return <>{children}</>;
}
