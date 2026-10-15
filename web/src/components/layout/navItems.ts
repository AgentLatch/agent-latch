/** Routes shown in the top navigation. Shared by the desktop bar and the mobile drawer. */
export interface NavItem {
  label: string;
  to: string;
}

export const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", to: "/" },
  { label: "Scans", to: "/scans" },
  { label: "Findings", to: "/findings" },
  { label: "Settings", to: "/settings" },
];
