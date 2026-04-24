package api

// ListQuery holds optional search/sort/page parameters for list endpoints.
type ListQuery struct {
	Q     string // partial-match keyword (empty = no filter)
	Sort  string // column name (validated against a whitelist by each method)
	Order string // "asc" or "desc"
	Page  int    // 1-based page number (default 1)
	Limit int    // items per page (default 100, max 1000)
}

func (lq ListQuery) order() string {
	if lq.Order == "asc" {
		return "ASC"
	}
	return "DESC"
}

func (lq ListQuery) clampedLimit() int {
	if lq.Limit <= 0 || lq.Limit > 1000 {
		return 100
	}
	return lq.Limit
}

func (lq ListQuery) offset() int {
	p := max(lq.Page, 1)
	return (p - 1) * lq.clampedLimit()
}

func (lq ListQuery) page() int {
	if lq.Page < 1 {
		return 1
	}
	return lq.Page
}

// PagedResult wraps a slice of items with pagination metadata.
type PagedResult[T any] struct {
	Total int64 `json:"total"`
	Page  int   `json:"page"`
	Limit int   `json:"limit"`
	Items []T   `json:"items"`
}
