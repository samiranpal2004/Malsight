const Ic = ({ children, size = 16, stroke = 1.5, className = '' }) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={stroke}
    strokeLinecap="round"
    strokeLinejoin="round"
    className={className}
  >
    {children}
  </svg>
);

export const IconUpload = (p) => (
  <Ic {...p}>
    <path d="M12 16V4" />
    <path d="M6 10l6-6 6 6" />
    <path d="M4 20h16" />
  </Ic>
);

export const IconLayers = (p) => (
  <Ic {...p}>
    <path d="M12 3l9 5-9 5-9-5 9-5z" />
    <path d="M3 13l9 5 9-5" />
    <path d="M3 18l9 5 9-5" />
  </Ic>
);

export const IconList = (p) => (
  <Ic {...p}>
    <path d="M8 6h13" />
    <path d="M8 12h13" />
    <path d="M8 18h13" />
    <circle cx="4" cy="6" r="1" />
    <circle cx="4" cy="12" r="1" />
    <circle cx="4" cy="18" r="1" />
  </Ic>
);

export const IconHex = (p) => (
  <Ic {...p}>
    <path d="M12 2l8.66 5v10L12 22 3.34 17V7L12 2z" />
  </Ic>
);

export const IconSearch = (p) => (
  <Ic {...p}>
    <circle cx="11" cy="11" r="7" />
    <path d="m20 20-3.5-3.5" />
  </Ic>
);

export const IconClock = (p) => (
  <Ic {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5l3 2" />
  </Ic>
);

export const IconArrowRight = (p) => (
  <Ic {...p}>
    <path d="M5 12h14" />
    <path d="M13 5l7 7-7 7" />
  </Ic>
);

export const IconCheck = (p) => (
  <Ic {...p}>
    <path d="M4 12l5 5L20 6" />
  </Ic>
);

export const IconShield = (p) => (
  <Ic {...p}>
    <path d="M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3z" />
  </Ic>
);

export const IconAlert = (p) => (
  <Ic {...p}>
    <path d="M12 3l10 17H2L12 3z" />
    <path d="M12 10v5" />
    <path d="M12 18h.01" />
  </Ic>
);

export const IconFile = (p) => (
  <Ic {...p}>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5z" />
    <path d="M14 3v5h5" />
  </Ic>
);

export const IconTerminal = (p) => (
  <Ic {...p}>
    <path d="M5 7l4 4-4 4" />
    <path d="M12 17h7" />
    <rect x="2.5" y="3.5" width="19" height="17" rx="2" />
  </Ic>
);

export const IconBox = (p) => (
  <Ic {...p}>
    <path d="M21 8L12 3 3 8v8l9 5 9-5V8z" />
    <path d="M3 8l9 5 9-5" />
    <path d="M12 13v8" />
  </Ic>
);

export const IconNetwork = (p) => (
  <Ic {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M3 12h18" />
    <path d="M12 3a14 14 0 0 1 0 18" />
    <path d="M12 3a14 14 0 0 0 0 18" />
  </Ic>
);

export const IconCpu = (p) => (
  <Ic {...p}>
    <rect x="6" y="6" width="12" height="12" rx="1.5" />
    <rect x="9" y="9" width="6" height="6" />
    <path d="M3 9h3M3 12h3M3 15h3M18 9h3M18 12h3M18 15h3M9 3v3M12 3v3M15 3v3M9 18v3M12 18v3M15 18v3" />
  </Ic>
);

export const IconLock = (p) => (
  <Ic {...p}>
    <rect x="4" y="11" width="16" height="10" rx="2" />
    <path d="M8 11V7a4 4 0 0 1 8 0v4" />
  </Ic>
);

export const IconKey = (p) => (
  <Ic {...p}>
    <circle cx="8" cy="14" r="4" />
    <path d="M11 11l9-9" />
    <path d="M16 6l3 3" />
  </Ic>
);

export const IconCopy = (p) => (
  <Ic {...p}>
    <rect x="8" y="8" width="12" height="12" rx="2" />
    <path d="M4 16V6a2 2 0 0 1 2-2h10" />
  </Ic>
);

export const IconChevronDown = (p) => (
  <Ic {...p}>
    <path d="M6 9l6 6 6-6" />
  </Ic>
);

export const IconPlay = (p) => (
  <Ic {...p}>
    <path d="M6 4l14 8-14 8V4z" />
  </Ic>
);

export const IconX = (p) => (
  <Ic {...p}>
    <path d="M6 6l12 12M18 6L6 18" />
  </Ic>
);

export const IconHash = (p) => (
  <Ic {...p}>
    <path d="M4 9h16M4 15h16M10 3l-2 18M16 3l-2 18" />
  </Ic>
);

export const IconBolt = (p) => (
  <Ic {...p}>
    <path d="M13 2L4 14h7l-1 8 9-12h-7l1-8z" />
  </Ic>
);

export const IconActivity = (p) => (
  <Ic {...p}>
    <path d="M3 12h4l3-9 4 18 3-9h4" />
  </Ic>
);

export const IconFolder = (p) => (
  <Ic {...p}>
    <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" />
  </Ic>
);

export const IconChip = (p) => (
  <Ic {...p}>
    <rect x="5" y="5" width="14" height="14" rx="2" />
    <path d="M9 9h6v6H9z" />
  </Ic>
);

export const IconExternal = (p) => (
  <Ic {...p}>
    <path d="M14 4h6v6" />
    <path d="M10 14L20 4" />
    <path d="M19 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h6" />
  </Ic>
);
