import pytest

from password_validator import (LengthValidator,
                                OneNumberValidator,
                                OneSpecialSignValidator,
                                LowercaseValidator,
                                UppercaseValidator,
                                HaveIBeenPwndValidator,
                                PasswordValidator,
                                ValidationError)


def test_password_length_with_given_length_positive():
    # given
    validator = LengthValidator('kokos', 5)

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_password_length_without_given_length_negative():
    # given
    validator = LengthValidator('ananas')

    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password is too short' in str(error.value)


def test_password_length_without_given_length_positive():
    # given
    validator = LengthValidator('ananas1234k')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_one_number_in_password_positive():
    # given
    validator = OneNumberValidator('awervsdf3dfsd')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_one_number_in_password_negative():
    # given
    validator = OneNumberValidator('asdfasdf')

    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password need at least one number' in str(error.value)


def test_one_special_sign_in_password_positive():
    # given
    validator = OneSpecialSignValidator('ksj#j')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_one_special_sign_in_password_negative():
    # given
    validator = OneSpecialSignValidator('ksjasdfa234fj')

    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password need one special sign' in str(error.value)


def test_lowercase_positive():
    # given
    validator = LowercaseValidator('ASDFKKJHd')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_lowercase_negative():
    # given
    validator = LowercaseValidator('ASDFH3#SKDJFK2$')

    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password need one lowercase letter' in str(error.value)


def test_uppercase_positive():
    # given
    validator = UppercaseValidator('kokosAsdf3#')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_uppercase_negative():
    # given
    validator = UppercaseValidator('ksjdf3#223$')

    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password need one uppercase letter' in str(error.value)


def test_pwnd_positive(requests_mock):
    # 'kh3#2hkH3$kL' = 73439764D3FF9424CED409C1CA1FF1FE1F911988
    # response ->   0019F550DC2F14C3BBC474592803160CB68:3
    #               015324F14AEF4B8376E3DDA3B229D635C40:3
    #               015AC7325D4BE94C9E5C2B3EB55DFBD10BC:1

    # given
    url = 'https://api.pwnedpasswords.com/range/73439'
    data = '0019F550DC2F14C3BBC474592803160CB68:3\n015324F14AEF4B8376E3DDA3B229D635C40:3\n015AC7325D4BE94C9E5C2B3EB55DFBD10BC:1'
    requests_mock.get(url, text=data)
    validator = HaveIBeenPwndValidator('kh3#2hkH3$kL')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_pwnd_negative(requests_mock):
    # 'admin123' = F865B53623B121FD34EE5426C792E5C33AF8C227
    # response ->   000B570293902B9C04CAE3847CC0D6C6111:1
    #               0039D94B368EE92C299990D8C95ADBE8940:6
    #               005B5A920AF36B7735BC64FE3A5511B1F6F:11
    #               53623B121FD34EE5426C792E5C33AF8C227:88830

    # given
    url = 'https://api.pwnedpasswords.com/range/F865B'
    data = '000B570293902B9C04CAE3847CC0D6C6111:15:1\n0039D94B368EE92C299990D8C95ADBE8940:6\n005B5A920AF36B7735BC64FE3A5511B1F6F:11\n53623B121FD34EE5426C792E5C33AF8C227:88830'
    requests_mock.get(url, text=data)
    validator = HaveIBeenPwndValidator('admin123')

    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password leaked, need to change password' in str(error.value)


def test_password_is_valid_positive():
    # given
    validator = PasswordValidator('Akj2331@3#khY')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_password_is_valid_negative():
    # given
    validator = PasswordValidator('ksdfKhd33Jhhe2')

    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password need one special sign' in str(error.value)


def test_password_is_valid_with_min_text_length_positive():
    # given
    validator = PasswordValidator('kokos23#2jsd#JKKD', 12)

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_password_is_valid_with_min_text_length_short_positive():
    # given
    validator = PasswordValidator('a3#D', 4)

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_password_is_valid_with_min_text_length_negative():
    # given
    validator = PasswordValidator('ksh#3#kaUekHke', 15)

    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password is too short' in str(error.value)
