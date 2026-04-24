interface Props {
  enabled: boolean
}

export function StatusBadge({ enabled }: Props) {
  return enabled ? (
    <span className="badge bg-success">有効</span>
  ) : (
    <span className="badge bg-secondary">無効</span>
  )
}
