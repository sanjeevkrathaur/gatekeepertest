package you.shall.not.pass.exception;

import lombok.Getter;
import you.shall.not.pass.domain.Access;

@Getter
public class NoAccessException extends RuntimeException {

    private final Access required;

    public NoAccessException(Access required, String message) {
        super(message);
        this.required = required;
    }

}
