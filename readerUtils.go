package main

import "io"

type readerReader struct {
	readFunc (func([]byte) (int, error))
}

func (rr *readerReader) Read(p []byte) (int, error) {
	return rr.readFunc(p)
}

func xorReader(r1 io.Reader, r2 io.Reader) io.Reader {
	readFunc := func(p []byte) (int, error) {
		b1 := make([]byte, 1)
		b2 := make([]byte, 1)
		n1 := -1
		// n2 := -1
		for _, i := range p {
			m1, err1 := r1.Read(b1)
			m2, err2 := r2.Read(b2)
			n1 = m1
			// n2 = m2
			if err1 != nil {
				return m1, err1
			}
			if err2 != nil {
				return m2, err2
			}
			p[i] = b1[0] ^ b2[0]
		}
		return n1, nil
	}
	return (&readerReader{readFunc: readFunc})
}
