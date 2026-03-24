export interface User {
  id: string;
  username: string;
  name: string;
  avatarColor: string;
  bio: string;
  followers: number;
  isTrending?: boolean;
  isRecentlyActive?: boolean;
}

export const MOCK_USERS: User[] = [
  { id: "1", username: "alex", name: "Alex Nova", avatarColor: "bg-indigo-500", bio: "Building QuickEx", followers: 1205, isTrending: true, isRecentlyActive: true },
  { id: "2", username: "sarah", name: "Sarah Chen", avatarColor: "bg-emerald-500", bio: "DeFi Researcher & Web3 dev", followers: 3420, isTrending: true, isRecentlyActive: false },
  { id: "3", username: "jordan", name: "Jordan Lee", avatarColor: "bg-rose-500", bio: "Crypto enthusiast", followers: 890, isTrending: false, isRecentlyActive: true },
  { id: "4", username: "taylor", name: "Taylor S", avatarColor: "bg-blue-500", bio: "Decentralizing music on Stellar", followers: 50400, isTrending: true, isRecentlyActive: true },
  { id: "5", username: "vitalik", name: "Vitalik B", avatarColor: "bg-purple-500", bio: "Not who you think it is, but I can code", followers: 432, isTrending: false, isRecentlyActive: true },
  { id: "6", username: "satoshin", name: "Satoshi N.", avatarColor: "bg-amber-500", bio: "Hide and seek champion", followers: 99999, isTrending: true, isRecentlyActive: false },
  { id: "7", username: "alice", name: "Alice Wonderland", avatarColor: "bg-pink-500", bio: "Down the Web3 rabbit hole", followers: 150, isTrending: false, isRecentlyActive: true },
  { id: "8", username: "bob", name: "Bob Builder", avatarColor: "bg-cyan-500", bio: "Can we build it? Yes we can.", followers: 230, isTrending: false, isRecentlyActive: false },
];
