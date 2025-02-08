package usecases

type UseCase[Input any, Output any] interface {
	Execute(Input) (Output, error)
}
