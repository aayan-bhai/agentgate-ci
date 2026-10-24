package main

type ToolOperation struct {
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Owner    string `json:"owner"`
}

func (s *MockState) recordToolOperation(req ToolRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.operations = append(s.operations, ToolOperation{
		Actor:    req.Actor,
		Action:   req.Action,
		Resource: req.Resource,
		Owner:    req.Owner,
	})
}

func (s *MockState) operationSnapshot() []ToolOperation {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]ToolOperation, len(s.operations))
	copy(result, s.operations)
	return result
}
